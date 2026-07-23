"""Deterministic command classifier. It parses text; it never executes it."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandClassification:
    executable: str
    command_class: str
    operation: str
    flags: tuple[str, ...]


_PRIVILEGE = {"sudo", "doas", "pkexec", "runas", "su"}
_CLOUD = {"aws", "az", "gcloud", "oci", "doctl"}
_CONTAINER = {"docker", "podman", "nerdctl"}
_KUBERNETES = {"kubectl", "oc", "helm"}


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return re.findall(r'"[^"]*"|\'[^\']*\'|\S+', command)


def classify_command(command: str | None) -> CommandClassification:
    tokens = _tokens(command or "")
    if not tokens:
        return CommandClassification("", "none", "none", ())
    executable = tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    args = [token.lower() for token in tokens[1:]]
    joined = (command or "").replace("\\", "/").lower()
    flags = tuple(token for token in args if token.startswith("-"))
    operation = args[0] if args else "execute"

    def invokes(names: set[str]) -> bool:
        alternatives = "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
        return bool(re.search(rf"(?:^|[;&|()\s'\"]|/)(?:{alternatives})(?:\.exe)?(?:\s|$)", joined))

    if invokes(_PRIVILEGE) or "start-process" in joined and re.search(r"\brunas\b", joined):
        command_class = "privilege_escalation"
    elif (
        invokes({"rm", "rmdir"})
        and bool(re.search(r"(?:^|\s)-(?:[a-z]*r[a-z]*|-{1,2}recursive)(?:\s|$)", joined))
        or "remove-item" in joined
        and "-recurse" in joined
        or invokes({"find"})
        and "-delete" in joined
    ):
        command_class = "recursive_delete"
    elif invokes({"ssh", "mosh", "sftp"}):
        command_class = "ssh_session"
    elif invokes({"git"}):
        command_class = "git"
        match = re.search(r"(?:^|[;&|()\s'\"]|/)git(?:\.exe)?\s+([a-z-]+)", joined)
        operation = match.group(1) if match else "unknown"
    elif invokes({"env", "set", "printenv"}) or (
        invokes({"powershell", "pwsh"}) and any(item in joined for item in ("env:", "get-childitem env"))
    ):
        command_class = "environment_harvest"
    elif invokes(_CLOUD):
        command_class = "cloud_cli"
        if re.search(r"\b(login|configure|get-token|get-access-token|credential)\b", joined):
            command_class = "cloud_credential"
    elif invokes(_CONTAINER):
        command_class = "container"
    elif invokes(_KUBERNETES):
        command_class = "kubernetes"
    elif any(term in joined for term in ("watchmyai", "elastic-agent", "auditd", "sysmon")) and any(
        term in joined for term in ("disable", "stop", "kill", "delete", "uninstall", "tamper")
    ):
        command_class = "security_control_tamper"
    else:
        command_class = "shell"
    return CommandClassification(executable, command_class, operation, flags)
