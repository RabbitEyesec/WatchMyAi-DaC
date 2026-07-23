#!/usr/bin/env bash
set -euo pipefail

EXIT_MISSING_PREREQUISITE=2
EXIT_INVALID_CONFIGURATION=3
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
BOOTSTRAP_ONLY=false
DEVELOPMENT=false

for argument in "$@"; do
  case "${argument}" in
    --bootstrap-only) BOOTSTRAP_ONLY=true ;;
    --dev) DEVELOPMENT=true ;;
    *) echo "Usage: $0 [--bootstrap-only] [--dev]" >&2; exit "${EXIT_MISSING_PREREQUISITE}" ;;
  esac
done

if [[ "${BOOTSTRAP_ONLY}" != true ]] && ! grep -qi '^ID=ubuntu' /etc/os-release 2>/dev/null; then
  echo "Linux installation supports Ubuntu; use --bootstrap-only for repository checks" >&2
  exit "${EXIT_MISSING_PREREQUISITE}"
fi

for command in git; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "Missing prerequisite: ${command}" >&2
    exit "${EXIT_MISSING_PREREQUISITE}"
  }
done
if [[ "${BOOTSTRAP_ONLY}" != true ]] && ! command -v curl >/dev/null 2>&1; then
  echo "Missing prerequisite: curl" >&2
  exit "${EXIT_MISSING_PREREQUISITE}"
fi

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
  echo "Python 3.11 or 3.12 is required" >&2
  exit "${EXIT_MISSING_PREREQUISITE}"
fi

"${PYTHON_COMMAND}" "${REPOSITORY_ROOT}/scripts/validate/validate_config.py" \
  --config "${REPOSITORY_ROOT}/.env.example" --template || exit "${EXIT_INVALID_CONFIGURATION}"

if [[ ! -x "${REPOSITORY_ROOT}/.venv/bin/python" ]]; then
  "${PYTHON_COMMAND}" -m venv "${REPOSITORY_ROOT}/.venv" || {
    echo "Unable to create .venv; on Ubuntu install python3-venv" >&2
    exit "${EXIT_MISSING_PREREQUISITE}"
  }
fi
VENV_PYTHON="${REPOSITORY_ROOT}/.venv/bin/python"
if ! "${VENV_PYTHON}" -c 'import sys; raise SystemExit(not ((3, 11) <= sys.version_info[:2] < (3, 13)))'; then
  echo "Existing .venv uses unsupported Python; recreate it with Python 3.11 or 3.12" >&2
  exit "${EXIT_MISSING_PREREQUISITE}"
fi

LOCK_FILE="${REPOSITORY_ROOT}/requirements-release.lock"
if [[ "${DEVELOPMENT}" == true ]]; then
  LOCK_FILE="${REPOSITORY_ROOT}/requirements-dev.lock"
fi
"${VENV_PYTHON}" -m pip install --require-hashes --requirement "${LOCK_FILE}"
"${VENV_PYTHON}" -m pip install --no-build-isolation --no-deps "${REPOSITORY_ROOT}"
"${VENV_PYTHON}" -m pip check
"${REPOSITORY_ROOT}/.venv/bin/watchmyai" --version

SMOKE_HOME="$(mktemp -d "${TMPDIR:-/tmp}/watchmyai-install-smoke.XXXXXX")"
trap 'rm -rf -- "${SMOKE_HOME}"' EXIT
"${REPOSITORY_ROOT}/.venv/bin/watchmyai" --home "${SMOKE_HOME}" init >/dev/null
WATCHMYAI_ALLOW_UNSIGNED_POLICY=1 \
  "${REPOSITORY_ROOT}/.venv/bin/watchmyai" --home "${SMOKE_HOME}" self-check >/dev/null

echo "PASS: WatchMyAI installed non-editably in ${REPOSITORY_ROOT}/.venv"
echo "Next: ${REPOSITORY_ROOT}/.venv/bin/watchmyai setup --repository-only --non-interactive --config ${REPOSITORY_ROOT}/.env"
