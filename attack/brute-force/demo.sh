#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
API_URL="${API_URL:-http://127.0.0.1:8000}"
TOKEN="${CYBER_ADMIN_TOKEN:-}"
if [[ -z "$TOKEN" && -f "$ROOT_DIR/.env" ]]; then
  TOKEN="$(sed -n 's/^CYBER_ADMIN_TOKEN=//p' "$ROOT_DIR/.env" | head -n 1)"
fi
case "$API_URL" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "Safety stop: API_URL must target localhost or 127.0.0.1." >&2; exit 2 ;;
esac
[[ -n "$TOKEN" ]] || { echo "Set CYBER_ADMIN_TOKEN or configure .env first." >&2; exit 2; }

SOURCE_IP="${SOURCE_IP:-198.51.100.80}"
ATTEMPTS="${ATTEMPTS:-6}"
[[ "$ATTEMPTS" =~ ^[0-9]+$ && "$ATTEMPTS" -ge 1 && "$ATTEMPTS" -le 10 ]] ||
  { echo "ATTEMPTS must be between 1 and 10." >&2; exit 2; }

echo "Safe failed-login telemetry demo against $API_URL"
for _ in $(seq 1 "$ATTEMPTS"); do
  curl --max-time 5 -sS -X POST "$API_URL/api/v1/events" \
    -H "Content-Type: application/json" \
    -H "X-Site-Key: $TOKEN" \
    -d "{\"site_id\":\"demo\",\"source_ip\":\"$SOURCE_IP\",\"path\":\"/login\",\"method\":\"POST\",\"failed_login\":true}"
  echo
done

