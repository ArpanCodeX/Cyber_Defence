# Universal Website Security Platform Test Report

Date: 2026-10-13

Testing was limited to the included local demo application. No public or
third-party systems were contacted. No uncontrolled flood or destructive test
was performed.

## Commands executed

```bash
python -m pytest -q
python -m py_compile app/main.py demo/app.py
cd dashboard && npm install --ignore-scripts && npm run build
timeout 5s uvicorn app.main:app --host 127.0.0.1 --port 18000
docker compose up --build
docker compose config --quiet
```

## Results

| Test | Expected behavior | Actual result | Status |
|---|---|---|---|
| Python automated suite | Existing and added API/security tests pass | 12 passed | PASS |
| Python syntax compilation | API and demo modules compile | Completed without errors | PASS |
| Real FastAPI process startup | Uvicorn starts and serves `/health` | Returned `status=healthy`, `database=ok`, `redis=disabled` | PASS |
| Normal event | Authenticated normal event is allowed and persisted | Passed in `test_normal_request_persists` | PASS |
| SQL injection signature | Harmless `union select` input is detected | `sql_injection` alert observed | PASS |
| XSS signature | Harmless script input is detected | `xss` alert observed | PASS |
| Rate threshold | More than configured requests raises `request_flood` | Alert observed | PASS |
| Brute force | Repeated failed logins trigger and block | 429 observed after threshold | PASS |
| Temporary IP block | Repeat offender remains blocked | 429 observed | PASS |
| Block expiry | Expired block no longer blocks | Event returned 200 after expiry update | PASS |
| Allowlists | Allowlisted source is not blocked | Repeated requests returned 200 | PASS |
| Emergency disable | Emergency disable prevents enforcement | Request returned 200 | PASS |
| IP spoofing | Untrusted forwarded header does not replace event IP | Original event IP retained | PASS |
| Authentication | Missing/wrong admin and site credentials are rejected | 401 observed | PASS |
| Tenant isolation | Unknown site cannot submit events | 401 observed | PASS |
| Malformed input | Invalid IP and oversized body are rejected | 422 observed | PASS |
| Health endpoint | Health reports database and Redis state | Database `ok`, Redis `disabled` in local test process | PASS |
| Dashboard empty/error handling | Empty data and API failures are visible | Empty-state and error UI added; browser execution not available | PARTIAL |
| React production build | Dashboard compiles using Vite | Initial attempt failed: missing `build` script; after fix `vite build` completed successfully | PASS |
| Gateway decision mapping | FastAPI rate decision supplies an Nginx-safe 429 marker | Added `X-Security-Status: 429`; automated test passed | PASS |
| Redis block state | Shared temporary blocks use Redis when configured | Redis set/get/delete with SQLite fallback implemented; live container not available | PARTIAL |
| Gateway startup race | Gateway waits for API and backend health | Compose health-based dependencies added; container startup not available | NOT RUN |
| One-command scripts | Start/status/stop work from any current directory | Syntax and Compose validation passed; runtime start blocked by this session's Docker socket sudo prompt | PARTIAL |
| Redis outage | Detection service continues using fallback | Fallback is implemented, but live Redis outage was not executable without Docker | NOT RUN |
| PostgreSQL connectivity | PostgreSQL is healthy and used | Docker unavailable; API local MVP uses SQLite | NOT RUN |
| Gateway/CRS startup | Nginx CRS routes demo and blocks in enforcement mode | Docker unavailable | NOT RUN |
| Full Compose clean start | All services become healthy | Docker CLI is not installed in this environment | NOT RUN |

## Bugs found and fixes applied

1. The dashboard had no `npm run build` command. Added the Vite build script
   and [dashboard/vite.config.js](dashboard/vite.config.js).
2. The API health endpoint only returned a generic healthy response. It now
   reports SQLite connectivity and Redis state and returns `degraded` if the
   database check fails.
3. The dashboard previously silently displayed an empty list when the API
   returned an error. It now displays an error message and a clear empty state.
4. Added automated coverage for health status, malformed/oversized input,
   allowlists, emergency disable, brute-force blocking, and block expiry.
5. Added a pre-proxy gateway decision endpoint and explicit Nginx status
   mapping so FastAPI decisions can reject traffic before the backend.
6. Added Redis-backed temporary block state with SQLite fallback and health
   based Compose startup ordering.
7. Added `start.sh`, `status.sh`, and `stop.sh` with permission checks,
   readiness polling, failure logs, and volume-preserving shutdown.

## Frontend build follow-up

The first build command failed because the package had no `build` script. The
configuration was corrected and the final `npm run build` completed
successfully, producing the Vite bundle in `dashboard/dist`.

## Known limitations and production gaps

- Docker and Docker Compose are unavailable in the execution environment, so
  the gateway, OWASP CRS image, Redis container, PostgreSQL container, demo
  container, and dashboard container could not be started here.
- The local API persistence path is SQLite. PostgreSQL is included in Compose
  with a reference migration but is not yet the active repository adapter.
- Redis is used for request counters when configured; temporary blocks remain
  in SQLite in this MVP.
- CRS-generated events are not automatically forwarded into the FastAPI event
  store; gateway logs and API-reported events are separate paths.
- Dashboard browser interaction was not executed because no browser automation
  or running container was available.
- The FastAPI application emits a deprecation warning for `on_event`; this is
  non-fatal and should be migrated to a lifespan handler before production.
- Production still requires TLS, secret management, PostgreSQL migrations,
  Redis-backed block state, origin isolation, stronger RBAC, monitoring,
  backups, and framework-specific adapters.
