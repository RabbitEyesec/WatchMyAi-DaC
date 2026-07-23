#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
PYTHON="${WATCHMYAI_PYTHON:-${REPOSITORY_ROOT}/.venv/bin/python}"

: "${KIBANA_URL:?Set KIBANA_URL, for example https://kibana.example.invalid}"
if [[ -z "${ELASTIC_API_KEY:-}" && -n "${ELASTIC_API_KEY_FILE:-}" ]]; then
  [[ -f "${ELASTIC_API_KEY_FILE}" ]] || {
    echo "ELASTIC_API_KEY_FILE is not readable" >&2
    exit 3
  }
  ELASTIC_API_KEY="$(tr -d '\r\n' < "${ELASTIC_API_KEY_FILE}")"
fi
: "${ELASTIC_API_KEY:?Set ELASTIC_API_KEY or ELASTIC_API_KEY_FILE}"

KIBANA_SPACE="${KIBANA_SPACE:-default}"
OUTPUT_PATH="${OUTPUT_PATH:-${REPOSITORY_ROOT}/dist/elastic-export.ndjson}"

if [[ ! "${KIBANA_SPACE}" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "KIBANA_SPACE may contain only letters, numbers, underscores, and hyphens" >&2
  exit 2
fi
if [[ ! -x "${PYTHON}" ]]; then
  echo "Missing repository Python: run scripts/install/install.sh first or set WATCHMYAI_PYTHON" >&2
  exit 2
fi
if [[ "${KIBANA_SPACE}" == "default" ]]; then
  SPACE_PATH=""
else
  SPACE_PATH="/s/${KIBANA_SPACE}"
fi

KIBANA_URL="${KIBANA_URL%/}"
mkdir -p "$(dirname "${OUTPUT_PATH}")"
REQUEST_BODY="$(mktemp -t watchmyai-export-request.XXXXXX)"
trap 'rm -f "${REQUEST_BODY}"' EXIT
"${PYTHON}" - "${REPOSITORY_ROOT}" "${REQUEST_BODY}" <<'PY'
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
from utilities.release_contract import SUPPORTED_IDS

Path(sys.argv[2]).write_text(
    json.dumps({"objects": [{"rule_id": rule_id} for rule_id in SUPPORTED_IDS]}),
    encoding="utf-8",
)
PY

printf 'header = "Authorization: ApiKey %s"\n' "${ELASTIC_API_KEY}" | curl --config - \
  --fail-with-body --silent --show-error \
  --request POST \
  "${KIBANA_URL}${SPACE_PATH}/api/detection_engine/rules/_export?exclude_export_details=true" \
  --header "Content-Type: application/json" \
  --header "kbn-xsrf: true" \
  --data-binary "@${REQUEST_BODY}" \
  --output "${OUTPUT_PATH}"

echo "Exported project rules to ${OUTPUT_PATH}"
