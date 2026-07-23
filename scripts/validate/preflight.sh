#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
PYTHON="${REPOSITORY_ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON}" ]]; then
  echo "Missing repository environment: run scripts/install/install.sh --bootstrap-only" >&2
  exit 2
fi
exec "${PYTHON}" "${REPOSITORY_ROOT}/scripts/preflight.py" "$@"
