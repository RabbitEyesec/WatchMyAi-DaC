"""watchmyai CLI.

Commands:
  setup                configure a cloned release from prerequisites to verified rules
  verify               verify deployment, fresh gateway telemetry, and a current WMAI-001 alert
  validate             generate deterministic telemetry and correlate all 20 current alerts
  self-check           validate packaged gateway resources without external services
  init                 create ~/.watchmyai (config, dirs, signature catalogue)
  discover             scan for running/installed AI agents and emit telemetry
  status               gateway + adapter status
  run -- <cmd>         wrap a CLI agent with generic telemetry
  install claude|codex|elastic
  uninstall [claude|codex]
  doctor               environment diagnosis
  hook claude|codex    internal lifecycle-hook entry point, reads stdin
  mcp-gateway -- <srv> policy-enforcing MCP stdio proxy

Pre-tool integration fails closed when policy, capability, evidence, or export
state cannot be evaluated. Secondary lifecycle telemetry remains best-effort.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import sysconfig
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from watchmyai import __version__
from watchmyai.gateway import Gateway, GatewayConfig, read_json_stdin

EXIT_VALIDATION = 6


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _gateway(args: argparse.Namespace) -> Gateway:
    return Gateway(GatewayConfig.load(getattr(args, "home", None)))


# ----------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    config = GatewayConfig.load(args.home)
    config.home.mkdir(mode=0o700, parents=True, exist_ok=True)
    config.home.chmod(0o700)
    for sub in (
        config.jsonl_path.parent,
        config.dead_letter_path.parent,
        config.approvals_store.parent,
        config.distribution_root,
    ):
        sub.mkdir(mode=0o700, parents=True, exist_ok=True)
        sub.chmod(0o700)
    if not config.config_path.exists():
        config.save_default()
    for name in ("agent_signatures.yml", "redaction.yml"):
        dst = config.home / name
        if not dst.exists():
            dst.write_bytes(resources.files("watchmyai.resources").joinpath(name).read_bytes())
            dst.chmod(0o600)
    if not config.unsigned_policy_bundle.exists():
        config.unsigned_policy_bundle.write_bytes(
            resources.files("watchmyai.resources").joinpath("policy-bundle.yml").read_bytes()
        )
        config.unsigned_policy_bundle.chmod(0o600)
    print(f"initialized {config.home}")
    print(f"  config:     {config.config_path}")
    print(f"  events:     {config.jsonl_path}")
    print(f"  signed:     {config.distribution_root / 'policy-store'}")
    print(f"  dev policy: {config.unsigned_policy_bundle} (disabled by default)")
    print(f"  deadletter: {config.dead_letter_path}")
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    from watchmyai.adapters.generic_desktop.monitor import discover_installed, discover_running
    from watchmyai.capture.process import capture_available
    from watchmyai.discovery.engine import DiscoveryEngine

    gw = _gateway(args)
    engine = DiscoveryEngine.from_config(gw.config.signatures_path)
    partials = discover_running(engine) + discover_installed(engine)
    emitted = 0
    for partial in partials:
        if gw.emit(partial) is not None:
            emitted += 1
    gw.flush()
    if not capture_available():
        print(
            "note: psutil not installed — running-process scan skipped (pip install 'WatchMyAI[capture]')",
            file=sys.stderr,
        )
    for partial in partials:
        agent = partial["watchmyai"]["agent"]
        attribution = partial["watchmyai"]["attribution"]["level"]
        action = partial["event"]["action"]
        pid = partial.get("process", {}).get("pid", "-")
        print(
            f"{action:<18} {agent.get('id', '?'):<20} pid={pid:<8} "
            f"confidence={agent.get('discovery_confidence', 0):<6} attribution={attribution}"
        )
    print(f"\n{len(partials)} discovery events, {emitted} emitted to {gw.config.output_mode}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    from watchmyai.adapters.claude_code import installer as claude_installer
    from watchmyai.adapters.codex_cli import installer as codex_installer

    gw = _gateway(args)
    _print(
        {
            "version": __version__,
            "gateway": gw.status(),
            "claude_code": claude_installer.status(),
            "codex_cli": codex_installer.status(),
        }
    )
    return 0


def _trusted_root_path(config: GatewayConfig) -> Path:
    return config.distribution_root / "trusted-root.json"


def _write_private_atomic(path: Path, content: bytes, *, refuse_existing: bool = False) -> None:
    if refuse_existing and path.exists():
        raise FileExistsError(f"{path} already exists; use signed sequential root rotation")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _distribution_client(gw: Gateway):
    from watchmyai.distribution.client import DistributionClient
    from watchmyai.distribution.metadata import RoleVerifier

    root_path = _trusted_root_path(gw.config)
    if not root_path.is_file():
        raise RuntimeError("trusted root is not enrolled; run 'watchmyai policy enroll-root'")
    raw = root_path.read_bytes()
    envelope = json.loads(raw)
    organization_id = envelope.get("signed", {}).get("organization_id")
    if not isinstance(organization_id, str) or not organization_id:
        raise ValueError("trusted root has no organization_id")
    verifier = RoleVerifier.enroll(raw, organization_id)
    endpoint_id = str(gw.normalizer.host.get("id") or gw.normalizer.host["name"])
    return DistributionClient(
        gw.config.distribution_root,
        verifier,
        endpoint_id=endpoint_id,
        agent_version=__version__,
        audit=gw.emit,
        root_persister=lambda content: _write_private_atomic(root_path, content),
    )


def cmd_policy(args: argparse.Namespace) -> int:
    from watchmyai.distribution.metadata import RoleVerifier

    gw = _gateway(args)
    if args.policy_command == "enroll-root":
        raw = Path(args.root).read_bytes()
        verifier = RoleVerifier.enroll(raw, args.organization_id)
        _write_private_atomic(_trusted_root_path(gw.config), raw, refuse_existing=True)
        gw.emit(
            {
                "event": {
                    "kind": "event",
                    "category": ["configuration"],
                    "type": ["change"],
                    "action": "distribution.root_enrolled",
                    "outcome": "success",
                },
                "watchmyai": {
                    "agent": {
                        "id": str(gw.normalizer.host.get("id") or gw.normalizer.host["name"]),
                        "type": "system",
                    },
                    "attribution": {"level": "confirmed"},
                    "session": {
                        "id": "distribution:"
                        + str(gw.normalizer.host.get("id") or gw.normalizer.host["name"])
                    },
                    "distribution": {
                        "state": "FRESH",
                        "role": "root",
                        "result": "enrolled",
                        "reason_code": "THRESHOLD_VERIFIED",
                        "metadata_versions": {"root": verifier.trusted_root["root_version"]},
                    },
                },
            }
        )
        gw.flush()
        _print(
            {"organization_id": args.organization_id, "root_version": verifier.trusted_root["root_version"]}
        )
        return 0

    client = _distribution_client(gw)
    if args.policy_command == "activate":
        release = Path(args.release_dir)
        result = client.verify_and_activate(
            timestamp_bytes=(release / "timestamp.json").read_bytes(),
            snapshot_bytes=(release / "snapshot.json").read_bytes(),
            targets_bytes=(release / "targets.json").read_bytes(),
            target_name=args.target_name,
            target_bytes=(release / args.target_name).read_bytes(),
            now=datetime.now(UTC),
            capability_validator=gw.capabilities.validate_distribution_requirements,
            rollback_approval_count=args.rollback_approval_count,
        )
        gw.flush()
        _print(result.__dict__)
        return 0
    if args.policy_command == "rotate-root":
        chain = [Path(item).read_bytes() for item in args.roots]
        client.rotate_root(chain, now=datetime.now(UTC))
        gw.flush()
        _print({"root_version": client.verifier.trusted_root["root_version"]})
        return 0

    state = dict(client.state)
    state["computed_offline_state"] = client.offline_state(datetime.now(UTC)).value
    state["active_path"] = str(client.store.read_pointer("ACTIVE") or "")
    state["last_known_good_path"] = str(client.store.read_pointer("LAST_KNOWN_GOOD") or "")
    gw.flush()
    _print(state)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from watchmyai.adapters.generic_cli.wrapper import run_wrapped

    gw = _gateway(args)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: watchmyai run [--agent ID] -- <agent command>", file=sys.stderr)
        return 2

    result = run_wrapped(command, gw.emit, agent_id=args.agent, passthrough=args.passthrough)
    gw.flush()
    print(
        f"[watchmyai] session={result.session_id} exit={result.exit_code} "
        f"duration={result.duration_seconds:.1f}s",
        file=sys.stderr,
    )
    return result.exit_code


def cmd_install(args: argparse.Namespace) -> int:
    if args.target == "claude":
        from watchmyai.adapters.claude_code import installer as claude_installer

        _print(claude_installer.install())
        return 0
    if args.target == "codex":
        from watchmyai.adapters.codex_cli import installer as codex_installer

        _print(codex_installer.install())
        return 0
    if args.target == "elastic":
        return _install_elastic(args)
    print(f"unknown install target: {args.target}", file=sys.stderr)
    return 2


def cmd_uninstall(args: argparse.Namespace) -> int:
    if args.target is None:
        from watchmyai.onboarding import uninstall

        return uninstall(args)
    if args.target == "claude":
        from watchmyai.adapters.claude_code import installer as claude_installer

        _print(claude_installer.uninstall())
        return 0
    if args.target == "codex":
        from watchmyai.adapters.codex_cli import installer as codex_installer

        _print(codex_installer.uninstall())
        return 0
    print(f"unknown uninstall target: {args.target}", file=sys.stderr)
    return 2


def cmd_approval(args: argparse.Namespace) -> int:
    """List or decide held approvals using only hashed public references."""
    gw = _gateway(args)
    if args.approval_command == "list":
        _print(gw.approvals.list_live())
        return 0
    if args.approval_command == "grant":
        approval = gw.approvals.grant_ref(args.approval_ref, justification=args.justification)
    else:
        approval = gw.approvals.reject_ref(args.approval_ref, justification=args.justification)
    gw.flush()
    if approval is None:
        print("approval not found, expired, or no longer pending", file=sys.stderr)
        return 1
    _print(
        {"approval_ref": approval.approval_ref, "status": approval.status, "action_id": approval.action_id}
    )
    return 0


def _install_elastic(args: argparse.Namespace) -> int:
    from watchmyai.exporters.elastic.exporter import ElasticSink, elastic_settings_from_env

    gw_config = GatewayConfig.load(args.home)
    dst = gw_config.home / "elastic"
    dst.mkdir(parents=True, exist_ok=True)
    repository_root = Path(__file__).resolve().parents[3]
    source_assets = repository_root / "telemetry-gateway" / "deployment" / "elastic"
    installed_assets = Path(sysconfig.get_path("data")) / "share" / "watchmyai" / "elastic"
    src = source_assets if source_assets.is_dir() else installed_assets
    if not src.is_dir():
        print("WatchMyAI Elastic assets are missing from this installation", file=sys.stderr)
        return 1
    copied = []
    if src.exists():
        for item in src.iterdir():
            shutil.copy2(item, dst / item.name)
            copied.append(item.name)
    print(f"Elastic assets copied to {dst}: {copied}")
    print(
        "\nNext steps (see "
        "https://github.com/rabbiteyesec/WatchMyAi-DaC/blob/main/"
        "telemetry-gateway/docs/ELASTIC_INTEGRATION.md):"
    )
    print("  1. export ELASTIC_URL=https://<your-cluster>:9243")
    print("  2. export ELASTIC_API_KEY=<api key with create_doc on logs-watchmyai.events-*>")
    print(f"  3. Load templates:   see {dst}/load-assets.sh")
    print(
        "  4. Either point Elastic Agent's custom-logs integration at "
        f"{gw_config.jsonl_path} (recommended), or set output.mode: elastic in "
        f"{gw_config.config_path}"
    )
    settings = elastic_settings_from_env()
    if settings:
        try:
            info = ElasticSink.from_env().test_connection()
            print(
                f"\nconnection test OK: cluster={info.get('cluster_name', '?')} "
                f"version={info.get('version', {}).get('number', '?')}"
            )
        except Exception as exc:  # noqa: BLE001
            print(f"\nconnection test FAILED: {exc}", file=sys.stderr)
            return 1
    else:
        print("\nELASTIC_URL not set — skipping connection test.")
    return 0


def cmd_self_check(args: argparse.Namespace) -> int:
    """Deterministic self-checks; exit 1 on any failure."""
    from watchmyai.discovery.signatures import SignatureCatalog
    from watchmyai.normalization.normalizer import Normalizer
    from watchmyai.policy.model import PolicyBundle
    from watchmyai.schema.event import load_schema, validate_event

    failures: list[str] = []

    def check(name: str, fn: Any) -> None:
        try:
            fn()
            print(f"PASS {name}")
        except Exception as exc:  # noqa: BLE001
            failures.append(name)
            print(f"FAIL {name}: {exc}")

    check("schema loads and is a valid JSON Schema", load_schema)

    def _roundtrip() -> None:
        event = Normalizer().normalize(
            {"event": {"category": ["session"], "type": ["start"], "action": "session_start"}}
        )
        errors = validate_event(event)
        if errors:
            raise ValueError(errors)

    check("normalizer produces schema-valid events", _roundtrip)

    gw_config = GatewayConfig.load(args.home)

    def _signatures() -> None:
        path = gw_config.signatures_path
        catalog = SignatureCatalog.load(path) if path else SignatureCatalog.load_default()
        if not catalog.signatures:
            raise ValueError(f"no signatures in {path or 'packaged catalogue'}")

    check("agent signature catalogue parses", _signatures)

    def _policies() -> None:
        packaged_policy = resources.files("watchmyai.resources").joinpath("policy-bundle.yml")
        with resources.as_file(packaged_policy) as policy_path:
            PolicyBundle.load(policy_path)

    check("packaged policy bundle parses", _policies)

    def _fixtures() -> None:
        repository_root = Path(__file__).resolve().parents[3]
        fixtures = repository_root / "telemetry-gateway" / "fixtures"
        if not fixtures.exists():
            return  # installed package: fixtures live in the repo only
        from watchmyai.adapters.claude_code.adapter import parse_hook_payload

        normalizer = Normalizer()
        for fx in sorted((fixtures / "claude_code").glob("*.json")):
            payload = json.loads(fx.read_text("utf-8"))
            for partial in parse_hook_payload(payload):
                normalizer.normalize(partial)

    check("claude fixtures normalize cleanly", _fixtures)
    if failures:
        print(f"\n{len(failures)} check(s) failed")
        return 1
    print("\nall checks passed")
    return 0


def cmd_setup(args: argparse.Namespace) -> int:
    from watchmyai.onboarding import setup

    return setup(args)


def cmd_verify(args: argparse.Namespace) -> int:
    from watchmyai.onboarding import verify

    return verify(args)


def cmd_validate(args: argparse.Namespace) -> int:
    from watchmyai.onboarding import validate

    return validate(args)


def cmd_doctor(args: argparse.Namespace) -> int:
    from watchmyai.adapters.claude_code import installer as claude_installer
    from watchmyai.adapters.codex_cli import installer as codex_installer
    from watchmyai.capture.process import capture_available
    from watchmyai.exporters.elastic.exporter import ElasticSink, elastic_settings_from_env
    from watchmyai.privacy.redaction import Redactor
    from watchmyai.schema.event import load_schema

    results: list[tuple[str, str, str]] = []  # (level, name, detail)

    def report(level: str, name: str, detail: str = "") -> None:
        results.append((level, name, detail))

    os_name = platform.system()
    report("PASS" if os_name in ("Darwin", "Linux", "Windows") else "FAIL", "supported OS", os_name)
    py = sys.version_info
    report(
        "PASS" if (3, 11) <= py[:2] < (3, 13) else "FAIL",
        "Python 3.11 or 3.12",
        platform.python_version(),
    )

    config = GatewayConfig.load(args.home)
    if config.home.exists():
        report("PASS", "watchmyai home exists", str(config.home))
    else:
        report("FAIL", "watchmyai home exists", f"{config.home} missing — run 'watchmyai init'")

    try:
        config.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        probe = config.jsonl_path.parent / ".wmai-doctor-probe"
        probe.write_text("ok")
        probe.unlink()
        report("PASS", "output directory writable", str(config.jsonl_path.parent))
    except OSError as exc:
        report("FAIL", "output directory writable", str(exc))

    gateway: Gateway | None = None
    try:
        gateway = Gateway(config)
        active = gateway.load_active_bundle()
        report("PASS", "signed active policy", f"{active.policy_bundle_id}@{active.policy_bundle_version}")
    except Exception as exc:  # noqa: BLE001
        report("FAIL", "signed active policy", str(exc))

    try:
        load_schema()
        report("PASS", "telemetry schema valid")
    except Exception as exc:  # noqa: BLE001
        report("FAIL", "telemetry schema valid", str(exc))

    redactor = Redactor.from_config(config.redaction_config)
    if redactor.enabled and redactor.rules:
        report("PASS", "redaction configured", f"{len(redactor.rules)} rules")
    else:
        report("WARN", "redaction configured", "redaction disabled or no rules — secrets may leak")

    report(
        "PASS" if capture_available() else "WARN",
        "psutil (process capture)",
        "" if capture_available() else "not installed — generic process scanning disabled",
    )

    claude = claude_installer.status()
    if claude.get("installed_events"):
        report("PASS", "Claude Code hooks", f"{len(claude['installed_events'])} events hooked")
    elif Path(claude["settings_path"]).parent.exists():
        report("WARN", "Claude Code hooks", "Claude installed but hooks absent — 'watchmyai install claude'")
    else:
        report("WARN", "Claude Code hooks", "Claude Code not detected on this host")

    codex = codex_installer.status()
    if codex.get("hooks_installed"):
        report("PASS", "Codex lifecycle hooks", codex["config_path"])
    elif Path(codex["config_path"]).parent.exists():
        report(
            "WARN",
            "Codex lifecycle hooks",
            "Codex installed but lifecycle hooks absent — 'watchmyai install codex'",
        )
    else:
        report("WARN", "Codex lifecycle hooks", "Codex CLI not detected on this host")

    report(
        "PASS" if shutil.which("watchmyai") else "WARN",
        "wrapper on PATH",
        "" if shutil.which("watchmyai") else "'watchmyai' not on PATH — hooks will fail to spawn",
    )

    try:
        elastic_environment = gateway.elastic_environment() if gateway else dict(os.environ)
    except (OSError, RuntimeError, ValueError) as exc:
        elastic_environment = {}
        report("FAIL", "Elastic configuration", str(exc))

    if elastic_settings_from_env(elastic_environment):
        try:
            info = ElasticSink.from_env(elastic_environment).test_connection()
            report("PASS", "Elastic connectivity", f"cluster={info.get('cluster_name', '?')}")
        except Exception as exc:  # noqa: BLE001
            report("FAIL", "Elastic connectivity", str(exc))
    else:
        report("WARN", "Elastic connectivity", "ELASTIC_URL not set (JSONL/Elastic Agent mode assumed)")

    width = max(len(name) for _, name, _ in results)
    failed = 0
    for level, name, detail in results:
        if level == "FAIL":
            failed += 1
        print(f"[{level:<4}] {name:<{width}}  {detail}")
    print(f"\n{len(results)} checks, {failed} failure(s)")
    return 1 if failed else 0


# ----------------------------------------------------------------------
def cmd_hook(args: argparse.Namespace) -> int:
    """Internal lifecycle hook. PreToolUse fails closed on every error."""
    payload = read_json_stdin(sys.stdin)
    if payload is None:
        print(json.dumps({"decision": "block", "reason": "WatchMyAI received invalid hook JSON"}))
        return 0
    try:
        gw = _gateway(args)
        if payload.get("hook_event_name") == "PreToolUse":
            runtime = gw.build_runtime()
            approval_id = os.environ.get("WATCHMYAI_APPROVAL_ID")
            if args.source == "claude":
                from watchmyai.adapters.claude_code.adapter import enforce_pre_tool as enforce_claude

                enriched = {**payload, **({"watchmyai_approval_id": approval_id} if approval_id else {})}
                _, response = enforce_claude(enriched, runtime)
            else:
                from watchmyai.adapters.codex_cli.adapter import enforce_pre_tool as enforce_codex

                _, response = enforce_codex(payload, runtime, approval_id)
            gw.flush()
            print(json.dumps(response, separators=(",", ":")))
            return 0
        if args.source == "claude":
            from watchmyai.adapters.claude_code.adapter import parse_hook_payload as parse_claude

            partials = parse_claude(payload)
        else:
            from watchmyai.adapters.codex_cli.adapter import parse_hook_payload as parse_codex

            partials = parse_codex(payload)
        for partial in partials:
            gw.emit(partial)
        gw.flush()
    except Exception as exc:  # noqa: BLE001
        print(f"[watchmyai hook error] {exc}", file=sys.stderr)
        if payload.get("hook_event_name") == "PreToolUse":
            print(
                json.dumps(
                    {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": (
                                "WatchMyAI failed closed: policy enforcement unavailable"
                            ),
                        }
                    },
                    separators=(",", ":"),
                )
            )
    return 0


def cmd_mcp_gateway(args: argparse.Namespace) -> int:
    from watchmyai.adapters.generic_mcp.gateway import run_proxy

    gw = _gateway(args)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("usage: watchmyai mcp-gateway [--name NAME] -- <mcp server command>", file=sys.stderr)
        return 2

    return run_proxy(command, gw.build_runtime(), gateway_name=args.name)


# ----------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchmyai", description="WatchMyAI Telemetry Gateway")
    parser.add_argument("--home", help="gateway home directory (default ~/.watchmyai)")
    parser.add_argument("--version", action="version", version=f"watchmyai {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the gateway home and default config").set_defaults(fn=cmd_init)
    sub.add_parser("discover", help="scan for AI agents").set_defaults(fn=cmd_discover)
    sub.add_parser("status", help="gateway and adapter status").set_defaults(fn=cmd_status)

    p_run = sub.add_parser("run", help="wrap a CLI agent with generic telemetry")
    p_run.add_argument("--agent", help="known agent id (e.g. codex_cli) for deep post-run ingestion")
    p_run.add_argument(
        "--passthrough", action="store_true", help="inherit stdio (for TUI agents); skips output metadata"
    )
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="-- <agent command>")
    p_run.set_defaults(fn=cmd_run)

    p_install = sub.add_parser("install", help="install an integration")
    p_install.add_argument("target", choices=["claude", "codex", "elastic"])
    p_install.set_defaults(fn=cmd_install)

    p_uninstall = sub.add_parser("uninstall", help="remove WatchMyAI or one integration")
    p_uninstall.add_argument("target", nargs="?", choices=["claude", "codex"])
    p_uninstall.add_argument("--config", default=".env")
    p_uninstall.add_argument("--yes", action="store_true", help="confirm the documented uninstall scope")
    p_uninstall.add_argument(
        "--purge-runtime",
        action="store_true",
        help="also remove the validated runtime home and retained local evidence",
    )
    p_uninstall.set_defaults(fn=cmd_uninstall)

    p_approval = sub.add_parser("approval", help="list, grant, or reject held actions")
    approval_sub = p_approval.add_subparsers(dest="approval_command", required=True)
    approval_sub.add_parser("list", help="list live approvals by hashed reference")
    for name in ("grant", "reject"):
        command = approval_sub.add_parser(name, help=f"{name} an approval")
        command.add_argument("approval_ref", help="exact approval hash or unique prefix")
        command.add_argument("--justification", required=True)
    p_approval.set_defaults(fn=cmd_approval)

    p_policy = sub.add_parser("policy", help="enroll, activate, rotate, or inspect signed policy")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)
    p_enroll = policy_sub.add_parser("enroll-root", help="perform first-use trusted-root enrollment")
    p_enroll.add_argument("root", help="signed root metadata envelope")
    p_enroll.add_argument("--organization-id", required=True)
    p_activate = policy_sub.add_parser("activate", help="verify and activate a signed release directory")
    p_activate.add_argument("release_dir")
    p_activate.add_argument("--target-name", default="policy.json")
    p_activate.add_argument("--rollback-approval-count", type=int, default=0)
    p_rotate = policy_sub.add_parser("rotate-root", help="apply sequential dual-threshold root envelopes")
    p_rotate.add_argument("roots", nargs="+")
    policy_sub.add_parser("status", help="show signed distribution and offline state")
    p_policy.set_defaults(fn=cmd_policy)

    p_setup = sub.add_parser("setup", help="perform the supported release onboarding workflow")
    p_setup.add_argument("--config", default=".env")
    p_setup.add_argument("--development", action="store_true", help="generate the safe development policy")
    p_setup.add_argument("--non-interactive", action="store_true")
    p_setup.add_argument("--repository-only", action="store_true", help=argparse.SUPPRESS)
    p_setup.add_argument("--elastic-url")
    p_setup.add_argument("--kibana-url")
    p_setup.add_argument("--fleet-url")
    p_setup.add_argument("--api-key-file")
    p_setup.add_argument("--elastic-agent-path")
    p_setup.add_argument("--fleet-policy-id")
    p_setup.add_argument("--signed-root", type=Path)
    p_setup.add_argument("--signed-policy-release", type=Path)
    p_setup.add_argument("--organization-id")
    p_setup.add_argument("--hooks", choices=["auto", "all", "claude", "codex", "none"], default="auto")
    p_setup.add_argument(
        "--enable-rules",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="explicitly enable or disable the imported production rules",
    )
    p_setup.add_argument("--allow-dirty", action="store_true", help=argparse.SUPPRESS)
    p_setup.set_defaults(fn=cmd_setup)

    p_verify = sub.add_parser("verify", help="verify the complete configured deployment")
    p_verify.add_argument("--config", default=".env")
    p_verify.add_argument("--repository-only", action="store_true", help=argparse.SUPPRESS)
    p_verify.add_argument("--allow-dirty", action="store_true", help=argparse.SUPPRESS)
    p_verify.set_defaults(fn=cmd_verify)

    p_validate = sub.add_parser("validate", help="generate and correlate deterministic rule telemetry")
    p_validate.add_argument("--config", default=".env")
    p_validate.add_argument("--static-only", action="store_true")
    p_validate.add_argument("--output")
    p_validate.set_defaults(fn=cmd_validate)
    sub.add_parser("self-check", help="validate packaged gateway resources").set_defaults(fn=cmd_self_check)
    sub.add_parser("doctor", help="diagnose the installation").set_defaults(fn=cmd_doctor)

    p_hook = sub.add_parser("hook", help="internal hook entry points")
    p_hook.add_argument("source", choices=["claude", "codex"])
    p_hook.set_defaults(fn=cmd_hook)

    p_mcp = sub.add_parser("mcp-gateway", help="policy-enforcing MCP stdio gateway")
    p_mcp.add_argument("--name", default="mcp", help="logical MCP server name for telemetry")
    p_mcp.add_argument("command", nargs=argparse.REMAINDER, help="-- <mcp server command>")
    p_mcp.set_defaults(fn=cmd_mcp_gateway)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd != "policy":
        try:
            return args.fn(args)
        except Exception as exc:  # onboarding errors must remain concise and secret-safe
            if args.cmd not in {"setup", "verify", "validate", "uninstall"}:
                raise
            from watchmyai.onboarding import OnboardingError

            if not isinstance(exc, (OnboardingError, OSError, RuntimeError, ValueError)):
                raise
            print(f"ERROR: {exc}", file=sys.stderr)
            return exc.exit_code if isinstance(exc, OnboardingError) else EXIT_VALIDATION

    from watchmyai.distribution.canonical import CanonicalJSONError
    from watchmyai.distribution.metadata import MetadataError

    try:
        return args.fn(args)
    except MetadataError as exc:
        reason_code = exc.code
    except CanonicalJSONError:
        reason_code = "INVALID_METADATA_JSON"
    except FileExistsError:
        reason_code = "POLICY_STATE_CONFLICT"
    except FileNotFoundError:
        reason_code = "POLICY_INPUT_UNAVAILABLE"
    except (json.JSONDecodeError, KeyError, OSError, RuntimeError, ValueError):
        reason_code = "POLICY_VERIFICATION_FAILED"
    print(
        f"ERROR: signed policy operation rejected ({reason_code}); no policy state was activated",
        file=sys.stderr,
    )
    return EXIT_VALIDATION


if __name__ == "__main__":
    sys.exit(main())
