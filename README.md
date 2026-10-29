# Universal Website Security Platform (local MVP)

This repository contains a backend-independent security control plane. It can
receive normalized events from Spring Boot, Node, Serverpod/Dart, Django,
Flask, Laravel, PHP, .NET, or any future adapter. It is intentionally
defense-in-depth: **Nginx + OWASP ModSecurity CRS is the HTTP enforcement
point**, while the FastAPI service persists events and evaluates integration
telemetry. If the API is unavailable, the gateway still applies its local CRS
rules.

## Start locally

Only test against this included demo service or systems you own/are explicitly
authorized to assess.

```bash
cp .env.example .env
# Replace the example token before starting if this is shared beyond your laptop.
./start.sh
```

Open the dashboard at <http://localhost:5174>, use the token as the
administrator password, and send traffic through <http://localhost:8080>.
`start.sh` builds and starts the dashboard from `dashboard/` together with the
API and gateway services.
The API is at <http://localhost:8000/docs>. The seeded `demo` site's event
credential is the same value as `CYBER_ADMIN_TOKEN` for local convenience;
use a separate generated per-site secret in a real deployment.

The default configuration is **detection-only**. To exercise blocking locally,
restart with `MODSEC_RULE_ENGINE=On ENFORCEMENT_MODE=enforcement`, and set a
site's policy `enforcement` to true. Keep an emergency
disable and allowlist configured to prevent administrator lockouts.

The gateway calls FastAPI's `/api/v1/gateway/check` before proxying. This
connects policy decisions to pre-backend enforcement. Denied checks return
403; temporary/rate blocks return 429.

Check service state with `./status.sh`. Stop everything with `./stop.sh`.
Use `./stop.sh --remove-orphans` to remove orphan containers. Add `-v` only when you intentionally
want to delete the local database volumes.

Use `./start.sh --rebuild` to force image rebuilding, or `./start.sh --logs`
to start and then follow live logs. These scripts work when called from any
directory and do not delete named volumes.

To use the simple Express demo instead of Flask, set this in `.env`:

```dotenv
BACKEND=http://express-demo:8081
```

Then restart Compose. The Express demo displays the method, path, query,
request body, and selected proxy headers as JSON. It is intentionally a
passive receiver and does not replace the event-reporting Flask demo.

### Deploy the protection gateway on Render

For a Render-hosted origin, deploy the gateway as the public service and keep
the origin URL private. The included [render.yaml](render.yaml) creates the
security API and gateway services:

1. Create a Render Blueprint from this repository.
2. Set `CYBER_ADMIN_TOKEN` and `SITE_KEY` to the same strong random value.
3. Set `BACKEND` to the Render URL of the application being protected, for
   example `https://my-app.onrender.com`.
4. Leave `SECURITY_API_URL` as `http://cyber-defense-api:8000` when using the
   Blueprint's API service.
5. Start with `MODSEC_RULE_ENGINE=DetectionOnly`, test the gateway URL, then
   change it to `On` after reviewing alerts.
6. Add your custom domain to `cyber-defense-gateway` in Render. Render
   supplies HTTPS for that domain.
7. Point DNS and your frontend/API clients at the gateway domain, not at the
   origin's `onrender.com` URL.

The request path is:

```text
client HTTPS -> Render gateway -> security API policy check -> Render origin
```

Never expose the origin URL to browsers or leave a public route that bypasses
the gateway. Render's HTTPS encrypts the client-to-gateway connection; the
gateway's ModSecurity and policy checks provide the additional protection.
This setup protects one configured origin. Multi-tenant arbitrary URL
forwarding requires allowlisted origins and SSRF protections before it is safe
to expose as a product.

Run the bounded local attack simulation:

```bash
CYBER_ADMIN_TOKEN="$(grep '^CYBER_ADMIN_TOKEN=' .env | cut -d= -f2-)" \
  ./scripts/demo_attack.sh
```

It sends a small, fixed burst only to the configured local gateway.

## Quick demo

The Compose default is detection-only. The demo API policy is configured with
a ten-request window so rate limiting can be demonstrated quickly. Events are
reported by the harmless demo backend to the API; no real website is contacted.

```bash
# Normal request passes through the gateway to the demo site.
curl -i http://localhost:8080/

# Simulated XSS is detected and recorded while detection-only is enabled.
curl -i 'http://localhost:8080/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'

# Generate enough requests to trigger the demo policy.
for n in $(seq 1 12); do curl -s -o /dev/null -H 'X-Demo-Client-IP: 198.51.100.20' http://localhost:8080/; done

# View recent events through the authenticated API.
curl -H "Authorization: Bearer $(grep '^CYBER_ADMIN_TOKEN=' .env | cut -d= -f2-)" \
  http://localhost:8000/api/v1/events
```

To explicitly enable app-side blocking, stop the stack, edit `.env`, and set:

```dotenv
ENFORCEMENT_MODE=enforcement
MODSEC_RULE_ENGINE=On
```

Then run `docker compose up --build` again. Update the demo policy through
`PUT /api/v1/sites/demo/policy` with `"enforcement": true`. A simulated XSS
returns 403; request floods and brute-force events return 429 and create a
temporary IP block. The block expires after the configured duration. For a
short local test, use `"block_duration_seconds": 10`.

## API and security model

- `POST /api/v1/events` requires the per-site `X-Site-Key`; `GET` and policy
  management endpoints require `Authorization: Bearer <CYBER_ADMIN_TOKEN>`.
- Create a site with `POST /api/v1/sites` and a JSON body containing
  `site_id`, `name`, and a randomly generated `credential` of at least 16
  characters. The returned credential is not shown again. Rotate it with
  `POST /api/v1/sites/{site_id}/rotate-credential`.
- Put the gateway in front of a site by changing `BACKEND` in
  `docker-compose.yml` (or the gateway environment) to the private origin
  URL. Keep the origin private so clients cannot bypass the gateway.
- Events are bounded and reject unknown fields. Stored records contain rule,
  timestamp, site, action, and reason, never passwords, tokens, or request
  bodies.
- `TRUSTED_PROXIES` is an explicit CIDR list. `X-Forwarded-For` is used only
  when the immediate peer is in that list; arbitrary clients cannot spoof IPs.
- Policies support request/login thresholds, temporary block duration,
  allowlists, detection/enforcement mode, and emergency disable.
- SQL injection and XSS signatures are additional WAF protection, **not a
  replacement for parameterized queries or safe output encoding**.
- HTTP inspection cannot detect every port scan and cannot prevent volumetric
  DDoS; port-scan events require authorized network telemetry (`event_type:
  port_probe`, `destination_port`).

Redis is used for distributed request counters when `REDIS_URL` is set (the
Compose stack sets it), with a bounded in-memory fallback for minimal local
tests. PostgreSQL is a private Compose service for the production topology.
This compact local build uses SQLite for zero-credential event persistence; apply
`migrations/001_initial.sql` and replace the repository adapter with PostgreSQL
and Redis in a hardened deployment. Do not expose either datastore publicly.
Use TLS, secret management, rotation, backups, and a private origin network in
production.

The Compose stack also includes `network-sensor`, a host-network Scapy sensor
that watches authorized lab traffic for common TCP and UDP port probes. It
classifies SYN, FIN, NULL, Xmas, ACK, and UDP probes. After the configured
number of distinct destination ports is seen for one source and scan type, it
reports `port_probe` telemetry with the scan type to the API. With enforcement
enabled, the API creates a temporary site/IP block that prevents subsequent
gateway requests from that source. The sensor needs `NET_RAW` and should only
run on a host and interface you own. It does not provide volumetric DDoS
protection or replace upstream firewall/CDN controls.

## Integration contract

Adapters POST JSON matching `app.main.Event` to `/api/v1/events` with
`X-Site-Key`. The included [integrations/express.js](integrations/express.js)
is a minimal reporter; adapters must enforce a returned block decision in
their own framework when they need backend-side blocking. An event collector
alone is never a blocking mechanism. Use short timeouts and fail closed only
where the application's availability policy explicitly permits it.

To view active blocks, call `GET /api/v1/sites/demo/blocks`. To unblock an IP
before expiry, call the authenticated
`DELETE /api/v1/sites/demo/blocks/198.51.100.20` endpoint, or add the address
to the site's allowlist using the policy endpoint. The dashboard currently
displays event history; block management remains in the authenticated API.

## Troubleshooting

- `docker compose ps` shows service state and health.
- `docker compose logs api gateway demo` shows startup and request errors.
- If ports are occupied, change the host-side values before the colon in
  `docker-compose.yml` (`8080`, `8000`, or `5174`).
- If the dashboard is empty, confirm the token in `.env` matches the token
  entered in the dashboard and that `docker compose logs api` has no errors.
- If a database schema is stale after development changes, use
  `docker compose down -v` and restart; this removes only local Compose data.

## Verification

```bash
python -m pip install -r requirements.txt
CYBER_ADMIN_TOKEN=test-admin-token-1234567890 pytest -q
```

The test suite covers normal events, signatures, rate thresholds, forwarding
header handling, authentication/tenant boundaries, persistence, and API
recovery. The external CRS container and volumetric behavior require Docker
and are documented limitations of this local MVP.
