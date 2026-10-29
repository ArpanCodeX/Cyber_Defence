#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
case "$BASE_URL" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "Safety stop: BASE_URL must target localhost or 127.0.0.1." >&2; exit 2 ;;
esac

echo "Safe XSS detection demo against $BASE_URL"
curl --max-time 5 -sS -i \
  "$BASE_URL/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

