#!/usr/bin/env bash
# Install the schema 1.1.0 Elastic assets and optional Kibana saved objects.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_FILE=""
if [[ $# -gt 0 ]]; then
  if [[ $# -ne 2 || "$1" != "--config" ]]; then
    echo "Usage: $0 [--config PATH]" >&2
    exit 2
  fi
  CONFIG_FILE="$2"
  [[ -f "${CONFIG_FILE}" ]] || {
    echo "Configuration file not found: ${CONFIG_FILE}" >&2
    exit 2
  }
fi

if [[ -n "${CONFIG_FILE}" ]]; then
  while IFS='=' read -r key value || [[ -n "${key:-}${value:-}" ]]; do
    key="${key%$'\r'}"
    value="${value%$'\r'}"
    [[ -z "${key}" || "${key}" == \#* ]] && continue
    if [[ ! "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo "Invalid configuration key in ${CONFIG_FILE}: ${key}" >&2
      exit 3
    fi
    if [[ -z "${!key+x}" ]]; then
      export "${key}=${value}"
    fi
  done < "${CONFIG_FILE}"
fi

ELASTIC_URL="${ELASTIC_URL:-${ELASTICSEARCH_URL:-}}"
ELASTIC_URL="${ELASTIC_URL%/}"
if [[ -z "${ELASTIC_URL}" ]]; then
  echo "Set ELASTIC_URL or ELASTICSEARCH_URL" >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "Missing prerequisite: curl" >&2
  exit 2
fi

CURL_TLS=()
case "${TLS_VERIFY:-true}" in
  true)
    if [[ -n "${ELASTIC_CA_CERT:-}" ]]; then
      [[ -f "${ELASTIC_CA_CERT}" ]] || {
        echo "ELASTIC_CA_CERT is not a readable file" >&2
        exit 3
      }
      CURL_TLS+=(--cacert "${ELASTIC_CA_CERT}")
    fi
    ;;
  false) CURL_TLS+=(--insecure) ;;
  *) echo "TLS_VERIFY must be true or false" >&2; exit 3 ;;
esac

CURL_AUTH=()
case "${ELASTIC_AUTH_METHOD:-api_key}" in
  api_key)
    if [[ -z "${ELASTIC_API_KEY:-}" && -n "${ELASTIC_API_KEY_FILE:-}" ]]; then
      [[ -f "${ELASTIC_API_KEY_FILE}" ]] || {
        echo "ELASTIC_API_KEY_FILE is not readable" >&2
        exit 3
      }
      ELASTIC_API_KEY="$(tr -d '\r\n' < "${ELASTIC_API_KEY_FILE}")"
    fi
    [[ -n "${ELASTIC_API_KEY:-}" ]] || {
      echo "API-key authentication requires ELASTIC_API_KEY or ELASTIC_API_KEY_FILE" >&2
      exit 3
    }
    CURL_AUTH+=(--header "Authorization: ApiKey ${ELASTIC_API_KEY}")
    ;;
  basic)
    [[ -n "${ELASTIC_USERNAME:-}" && -n "${ELASTIC_PASSWORD:-}" ]] || {
      echo "Basic authentication requires ELASTIC_USERNAME and ELASTIC_PASSWORD" >&2
      exit 3
    }
    CURL_AUTH+=(--user "${ELASTIC_USERNAME}:${ELASTIC_PASSWORD}")
    ;;
  *) echo "ELASTIC_AUTH_METHOD must be api_key or basic" >&2; exit 3 ;;
esac

request() {
  curl --fail-with-body --silent --show-error "${CURL_TLS[@]}" "${CURL_AUTH[@]}" "$@"
}

put_asset() {
  local label="$1"
  local url="$2"
  local file="$3"
  echo "Installing ${label}"
  request --request PUT "${url}" --header "Content-Type: application/json" \
    --data-binary "@${file}"
  echo
}

put_asset "ILM policy" "${ELASTIC_URL}/_ilm/policy/watchmyai-events" "${HERE}/ilm_policy.json"
put_asset "component template" "${ELASTIC_URL}/_component_template/watchmyai-events-mappings" "${HERE}/component_template.json"
put_asset "ingest pipeline" "${ELASTIC_URL}/_ingest/pipeline/watchmyai-events" "${HERE}/ingest_pipeline.json"
put_asset "index template" "${ELASTIC_URL}/_index_template/logs-watchmyai.events" "${HERE}/index_template.json"

if ! request "${ELASTIC_URL}/_data_stream/logs-watchmyai.events-default" >/dev/null; then
  echo "Creating data stream logs-watchmyai.events-default"
  request --request PUT "${ELASTIC_URL}/_data_stream/logs-watchmyai.events-default"
  echo
fi

if [[ -n "${KIBANA_URL:-}" ]]; then
  KIBANA_URL="${KIBANA_URL%/}"
  KIBANA_SPACE="${KIBANA_SPACE:-default}"
  if [[ ! "${KIBANA_SPACE}" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "KIBANA_SPACE may contain only letters, numbers, underscores, and hyphens" >&2
    exit 3
  fi
  SPACE_PATH=""
  if [[ "${KIBANA_SPACE}" != "default" ]]; then
    SPACE_PATH="/s/${KIBANA_SPACE}"
  fi
  echo "Importing optional WatchMyAI Kibana data view and saved searches"
  if request --request POST \
    "${KIBANA_URL}${SPACE_PATH}/api/saved_objects/_import?overwrite=true" \
    --header "kbn-xsrf: watchmyai-v1" \
    --form "file=@${HERE}/kibana.ndjson;type=application/ndjson"; then
    echo
  else
    echo "WARNING: optional Kibana searches were not imported; telemetry and rule setup will continue" >&2
  fi
fi

echo "WatchMyAI schema 1.1.0 Elastic assets installed"
