#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-127.0.0.1}"
PORTS="${PORTS:-3000-3010}"
[[ "$TARGET" == "127.0.0.1" || "$TARGET" == "localhost" ]] ||
  { echo "Safety stop: TARGET must be localhost or 127.0.0.1." >&2; exit 2; }
command -v nmap >/dev/null 2>&1 || { echo "nmap is not installed." >&2; exit 2; }

echo "Safe local TCP connect-scan demo: $TARGET ports $PORTS"
nmap -sT -T2 --max-retries 1 --host-timeout 10s -p "$PORTS" "$TARGET"

