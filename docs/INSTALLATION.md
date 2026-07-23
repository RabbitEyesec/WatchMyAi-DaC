# Installation and lifecycle

The [quick start](QUICKSTART.md) is the supported first-user path. This document defines package
installation, platform boundaries, upgrades, and reinstalls.

## Supported environment

| Area | v1.0.0 support |
| --- | --- |
| Python | 3.11 and 3.12 |
| Connected deployment host | Ubuntu 24.04 |
| Elastic | Elasticsearch, Kibana, Fleet Server, and Elastic Agent 9.4.3 |
| Windows | Bootstrap installer and repository tests; connected Elastic deployment not validated |

The Bash installer rejects non-Ubuntu live installation. `--bootstrap-only` exists for repository
checks on another host. This does not extend the validated live deployment claim.
The v1.0.0 live onboarding contract remains Ubuntu 24.04.

## External prerequisites

Before setup, an operator must provide:

- reachable Elasticsearch, Kibana, and Fleet Server 9.4.3 HTTPS endpoints;
- Elastic Agent 9.4.3 installed, enrolled, and healthy on the deployment host;
- CA files when the issuing CA is not in the host trust store;
- the local Elastic Agent executable path; and
- a scoped WatchMyAI credential.

The credential must cover only the workflow operations: manage the named WatchMyAI ILM policy,
templates, pipeline, and data stream; manage the 20 Detection Engine rules; read Fleet agents,
policies, and packages; add an Elastic Defend package policy; write controlled validation
documents; and read WatchMyAI telemetry, supported native file sources, and Elastic Security alert
indices. Optional Kibana saved-object import needs corresponding saved-object privileges.

WatchMyAI does not provision Elastic services, enroll Agent, issue TLS certificates, create a
production signing authority, or manage the organization's credential lifecycle.

## Install on Ubuntu

From a fresh checkout:

```bash
./scripts/install/install.sh
```

The installer:

1. selects Python 3.12 or 3.11;
2. validates `.env.example` as a template;
3. creates `.venv` when absent;
4. installs `requirements-release.lock` with hashes;
5. installs the root package non-editably and without dependency re-resolution;
6. runs `pip check`, version output, `init`, and `self-check` in isolated state.

It does not write `.env`, create production runtime state, contact Elastic, install hooks, or import
rules. Those operations belong to `watchmyai setup`.

Use `./scripts/install/install.sh --dev` only for contributor tooling. The contributor lock adds
formatting, typing, and security tools; it is not needed for a normal runtime installation.

## Bootstrap on Windows

From PowerShell:

```powershell
& .\scripts\install\install.ps1
```

The script uses Python 3.12 or 3.11, creates `.venv`, applies the same hash-locked runtime and
validation environment, and runs package smoke checks. Use `-Dev` for contributor tools. Windows
bootstrap support does not claim that the complete live Elastic path was validated on Windows.

## Install from a release package

The root release builder produces a wheel and source distribution. In an environment that already
contains the reviewed locked dependencies, install a verified wheel without resolving new ones:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-release.lock
.venv/bin/python -m pip install --no-deps dist/watchmyai-1.0.0-py3-none-any.whl
.venv/bin/watchmyai --version
```

Repository-backed `setup`, rule import, and live validation also require the matching source
checkout because they consume reviewed root assets. A standalone wheel supports gateway primitives
and `self-check`, but it is not a replacement for the one-project deployment workflow.

## Runtime and contributor dependency boundaries

- `requirements-release.lock` contains runtime plus repository-validation dependencies used by the
  installer and release gates.
- `requirements-dev.lock` contains the contributor and security toolchain.
- `pyproject.toml` defines the single package, supported Python range, entry point, and dependency
  intent.

Do not run an unlocked `pip install -e .` as the release installation path. Do not modify a lock to
work around a network, Python-version, or platform failure.

## Clean-checkout expectation

A clean checkout contains no `.env`, `.venv`, runtime home, build output, cached test data, live
evidence, or credentials. Installation may create ignored `.venv`; setup later creates ignored
`.env` and runtime state outside the repository. Repository-only validation must not be described as
a connected Elastic deployment.

## Upgrade

Review and update the checkout using the repository owner's normal Git workflow, then run:

```bash
./scripts/install/install.sh
.venv/bin/watchmyai setup --development
.venv/bin/watchmyai verify
.venv/bin/watchmyai validate
```

For signed production, rerun setup with the organization-approved signed inputs instead of
`--development`. Setup updates its managed assets by stable name and ID and preserves unrelated
hooks and Fleet integrations. A policy sequence or version change still requires a correctly
signed release.

## Reinstall

```bash
.venv/bin/watchmyai uninstall --yes
./scripts/install/install.sh
.venv/bin/watchmyai setup --development
.venv/bin/watchmyai verify
.venv/bin/watchmyai validate
```

Normal uninstall preserves local audit evidence and external Elastic data. Use
`--purge-runtime` only after retention approval and after confirming the exact configured runtime
home. See [Uninstall](UNINSTALL.md).

Related documents: [Setup and configuration](SETUP_AND_CONFIGURATION.md),
[Configuration reference](CONFIGURATION.md), and [Troubleshooting](TROUBLESHOOTING.md).
