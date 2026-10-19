#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  printf 'ERROR: Docker is not installed or is not on PATH.\n' >&2
  exit 1
fi

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif sudo -n docker info >/dev/null 2>&1 || sudo -v; then
  DOCKER=(sudo docker)
else
  printf 'ERROR: Cannot access the Docker daemon.\n' >&2
  exit 1
fi

"${DOCKER[@]}" compose ps
