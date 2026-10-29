#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:8080/}"
REQUESTS="${REQUESTS:-25}"
WORKERS="${WORKERS:-5}"
case "$BASE_URL" in
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "Safety stop: BASE_URL must target localhost or 127.0.0.1." >&2; exit 2 ;;
esac
[[ "$REQUESTS" =~ ^[0-9]+$ && "$REQUESTS" -ge 1 && "$REQUESTS" -le 100 ]] ||
  { echo "REQUESTS must be between 1 and 100." >&2; exit 2; }
[[ "$WORKERS" =~ ^[0-9]+$ && "$WORKERS" -ge 1 && "$WORKERS" -le 10 ]] ||
  { echo "WORKERS must be between 1 and 10." >&2; exit 2; }

echo "Bounded local request-flood demo: $REQUESTS requests, $WORKERS workers"
python "$ROOT_DIR/tools/safe_load_test.py" \
  --url "$BASE_URL" --requests "$REQUESTS" --workers "$WORKERS"

