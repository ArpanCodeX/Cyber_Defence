#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

usage() {
  printf 'Usage: %s [--rebuild] [--logs]\n' "$0"
}

REBUILD=0
LOGS=0
for arg in "$@"; do
  case "$arg" in
    --rebuild) REBUILD=1 ;;
    --logs) LOGS=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  printf 'ERROR: Docker is not installed or is not on PATH.\n' >&2
  exit 1
fi

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif sudo -n docker info >/dev/null 2>&1 || sudo -v; then
  DOCKER=(sudo docker)
else
  printf 'ERROR: Docker is installed, but this user cannot access the Docker daemon.\n' >&2
  printf 'Run: sudo usermod -aG docker "$USER" and log in again.\n' >&2
  exit 1
fi

if ! "${DOCKER[@]}" compose version >/dev/null 2>&1; then
  printf 'ERROR: Docker Compose plugin is unavailable.\n' >&2
  printf 'Install the Docker Compose plugin, then rerun ./start.sh.\n' >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  if [[ ! -f .env.example ]]; then
    printf 'ERROR: Neither .env nor .env.example exists.\n' >&2
    exit 1
  fi
  cp .env.example .env
  printf 'Created .env from .env.example. Review local secrets before sharing this host.\n'
fi

COMPOSE=("${DOCKER[@]}" compose)
SERVICES=(redis postgres api demo express-demo gateway dashboard network-sensor)

if (( REBUILD )); then
  "${COMPOSE[@]}" build --pull "${SERVICES[@]}"
else
  "${COMPOSE[@]}" build "${SERVICES[@]}"
fi

"${COMPOSE[@]}" up -d "${SERVICES[@]}"

printf 'Waiting for services to become ready'
deadline=$((SECONDS + 180))
while (( SECONDS < deadline )); do
  ready=1
  for service in "${SERVICES[@]}"; do
    container="$("${COMPOSE[@]}" ps -q "$service" 2>/dev/null || true)"
    if [[ -z "$container" ]]; then
      ready=0
      continue
    fi
    state="$( "${DOCKER[@]}" inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)"
    health="$( "${DOCKER[@]}" inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$container" 2>/dev/null || true)"
    if [[ "$state" != "running" || ( "$health" != "healthy" && "$health" != "no-healthcheck" ) ]]; then
      ready=0
    fi
  done
  if (( ready )); then
    printf ' ready.\n'
    break
  fi
  printf '.'
  sleep 2
done

if (( ! ready )); then
  printf '\nERROR: The stack did not become ready within 180 seconds.\n' >&2
  "${COMPOSE[@]}" ps >&2 || true
  printf '\nRecent logs:\n' >&2
  "${COMPOSE[@]}" logs --tail=80 gateway api demo express-demo >&2 || true
  exit 1
fi

if command -v curl >/dev/null 2>&1; then
  if ! curl --fail --silent --show-error http://localhost:8000/health >/dev/null; then
    printf 'ERROR: API health endpoint is not reachable on port 8000.\n' >&2
    "${COMPOSE[@]}" logs --tail=80 api >&2 || true
    exit 1
  fi
  if ! curl --fail --silent --show-error http://localhost:8080/health >/dev/null; then
    printf 'ERROR: Gateway health endpoint is not reachable on port 8080.\n' >&2
    "${COMPOSE[@]}" logs --tail=80 gateway >&2 || true
    exit 1
  fi
  if ! curl --fail --silent --show-error http://localhost:5174 >/dev/null; then
    printf 'ERROR: Dashboard is not reachable on port 5174.\n' >&2
    "${COMPOSE[@]}" logs --tail=80 dashboard >&2 || true
    exit 1
  fi
fi

printf '\nUniversal Website Security Platform is ready.\n'
printf 'Dashboard:       http://localhost:5174\n'
printf 'Demo gateway:    http://localhost:8080\n'
printf 'API docs:        http://localhost:8000/docs\n'
printf 'Health endpoint: http://localhost:8000/health\n'

if (( LOGS )); then
  exec "${COMPOSE[@]}" logs -f
fi
