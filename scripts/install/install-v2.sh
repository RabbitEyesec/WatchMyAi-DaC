#!/usr/bin/env bash
# One-command setup for the WatchMyAI Version 2 toolchain (Sigma, Sysmon, D3FEND) on Linux/macOS.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

PYTHON_COMMAND=""
for candidate in python3.12 python3.11 python3; do
  if command -v "${candidate}" >/dev/null 2>&1 &&
    "${candidate}" -c 'import sys; raise SystemExit(not ((3, 11) <= sys.version_info[:2] < (3, 13)))'
  then
    PYTHON_COMMAND="${candidate}"
    break
  fi
done
if [[ -z "${PYTHON_COMMAND}" ]]; then
  echo "Python 3.11 or 3.12 is required. Install it, then run this script again." >&2
  exit 2
fi

echo "==> Creating the virtual environment (.venv)"
if [[ ! -x "${REPOSITORY_ROOT}/.venv/bin/python" ]]; then
  "${PYTHON_COMMAND}" -m venv "${REPOSITORY_ROOT}/.venv" || {
    echo "Could not create .venv; on Ubuntu run: sudo apt install python3-venv" >&2
    exit 2
  }
fi
VENV_PYTHON="${REPOSITORY_ROOT}/.venv/bin/python"

echo "==> Installing WatchMyAI and the Version 2 tools (hash-pinned)"
"${VENV_PYTHON}" -m pip install --quiet --require-hashes --requirement "${REPOSITORY_ROOT}/requirements-dev.lock"
"${VENV_PYTHON}" -m pip install --quiet --no-build-isolation --no-deps "${REPOSITORY_ROOT}"

echo "==> Running the Version 2 toolchain"
(cd "${REPOSITORY_ROOT}" && "${VENV_PYTHON}" scripts/run_v2_integrations.py)

cat <<MESSAGE

WatchMyAI Version 2 is ready.

  Run everything again:   .venv/bin/python scripts/run_v2_integrations.py
  Sigma candidates:       dist/sigma-candidates/
  Windows Sysmon setup:   see docs/V2_INTEGRATIONS.md (scripts/install/install-sysmon.ps1)
  Check Sysmon in Elastic: .venv/bin/python scripts/validate/verify_sysmon_ingest.py
MESSAGE
