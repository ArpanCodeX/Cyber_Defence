#!/usr/bin/env bash
set -u

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
API_URL="${API_URL:-http://127.0.0.1:8000}"
TOKEN="${CYBER_ADMIN_TOKEN:-}"
BURST="${BURST:-12}"
WAIT_SECONDS="${WAIT_SECONDS:-0}"
failures=0

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; failures=$((failures + 1)); }
status() { curl --max-time 5 -sS -o /tmp/security-demo-response -w '%{http_code}' "$@"; }

printf 'Testing only %s\n' "$BASE_URL"

code="$(status "$BASE_URL/")"
[[ "$code" == "200" ]] && pass "normal request reaches the backend" || fail "normal request returned $code"

code="$(status "$BASE_URL/search?q=union%20select")"
[[ "$code" == "200" || "$code" == "403" ]] && pass "SQL injection pattern handled ($code)" || fail "SQL injection test returned $code"

code="$(status "$BASE_URL/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")"
[[ "$code" == "200" || "$code" == "403" ]] && pass "XSS pattern handled ($code)" || fail "XSS test returned $code"

for _ in $(seq 1 "$BURST"); do
  curl --max-time 5 -sS -o /dev/null "$BASE_URL/" || true
done

if [[ -n "$TOKEN" ]]; then
  blocks="$(curl --max-time 5 -sS -H "Authorization: Bearer $TOKEN" \
    "$API_URL/api/v1/sites/demo/blocks")"
  if python -c 'import json,sys; rows=json.load(sys.stdin); sys.exit(0 if rows else 1)' <<<"$blocks"; then
    pass "at least one IP is listed as temporarily blocked"
  else
    printf 'INFO: no active block; use ENFORCEMENT_MODE=enforcement and a policy with enforcement=true\n'
  fi
else
  printf 'INFO: set CYBER_ADMIN_TOKEN to check the authenticated block API\n'
fi

if (( WAIT_SECONDS > 0 )); then
  sleep "$WAIT_SECONDS"
  code="$(status "$BASE_URL/")"
  [[ "$code" == "200" ]] && pass "request works after expiry wait" || fail "request after expiry returned $code"
fi

printf 'Summary: %d failure(s)\n' "$failures"
exit "$failures"
