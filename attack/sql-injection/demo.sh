#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
case "$BASE_URL" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "Safety stop: BASE_URL must target localhost or 127.0.0.1." >&2; exit 2 ;;
esac

echo "Safe SQL injection detection demo against $BASE_URL"
curl --max-time 5 -sS -i \
  "$BASE_URL/search?q=union%20select%20username%20from%20users"

