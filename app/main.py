"""Backend-independent security event API.

The gateway remains the first enforcement point. This service stores events,
evaluates integration-reported telemetry, and provides management APIs.
"""
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any
from urllib.parse import unquote_plus
try:
    import redis
except ImportError:  # local minimal installs can still use the bounded fallback
    redis = None

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("CYBER_DB_PATH", str(APP_DIR / "events.db")))
ADMIN_TOKEN = os.getenv("CYBER_ADMIN_TOKEN", os.getenv("CYBER_API_KEY", ""))
ENFORCEMENT = os.getenv("ENFORCEMENT_MODE", "detection").lower() == "enforcement"
TRUSTED_PROXIES = {
    ipaddress.ip_network(value.strip())
    for value in os.getenv("TRUSTED_PROXIES", "127.0.0.1/32,::1/128").split(",")
    if value.strip()
}
REDIS_URL = os.getenv("REDIS_URL", "")
redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True,
                                     socket_connect_timeout=1, socket_timeout=1) if redis and REDIS_URL else None

app = FastAPI(title="Universal Website Security Platform", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
                   allow_methods=["GET", "POST", "PUT"], allow_headers=["*"])

windows: dict[tuple[str, str], deque[float]] = defaultdict(deque)
failed_logins: dict[tuple[str, str], deque[float]] = defaultdict(deque)
port_probes: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
temporary_blocks: dict[tuple[str, str], float] = {}

SQLI_PATTERNS = [re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I), re.compile(r"\b(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.I),
                 re.compile(r"(?:--|/\*|\*/|;\s*drop\s+)", re.I), re.compile(r"\bselect\b.+\bfrom\b", re.I)]
XSS_PATTERNS = [re.compile(r"<\s*script\b", re.I), re.compile(r"javascript\s*:", re.I),
                re.compile(r"\bon(?:error|load|click)\s*=", re.I)]


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    site_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    source_ip: str = Field(min_length=1, max_length=64)
    path: str = Field(default="/", max_length=2048)
    method: str = Field(default="GET", max_length=12, pattern=r"^[A-Za-z]+$")
    body: str = Field(default="", max_length=10000)
    failed_login: bool = False
    event_type: str = Field(default="http_request", max_length=64)
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    severity: str = Field(default="info", pattern=r"^(info|low|medium|high|critical)$")
    rule_id: str | None = Field(default=None, max_length=100)

    @field_validator("source_ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value


class Policy(BaseModel):
    request_limit: int = Field(default=120, ge=1, le=100000)
    window_seconds: int = Field(default=60, ge=1, le=3600)
    login_limit: int = Field(default=5, ge=1, le=1000)
    block_duration_seconds: int = Field(default=900, ge=10, le=86400)
    enforcement: bool = False
    allowlist: list[str] = Field(default_factory=list, max_length=100)
    emergency_disable: bool = False


class Site(BaseModel):
    site_id: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
    name: str = Field(min_length=1, max_length=200)
    credential: str = Field(min_length=16, max_length=256)


def connect_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS sites (site_id TEXT PRIMARY KEY, name TEXT NOT NULL, credential_hash TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS policies (site_id TEXT PRIMARY KEY, config TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS security_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, site_id TEXT NOT NULL,
          source_ip TEXT NOT NULL, path TEXT NOT NULL, method TEXT NOT NULL, event_type TEXT NOT NULL,
          alerts TEXT NOT NULL, severity TEXT NOT NULL, action TEXT NOT NULL, rule_id TEXT, reason TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ip_blocks (
          site_id TEXT NOT NULL, source_ip TEXT NOT NULL, expires_at TEXT NOT NULL, reason TEXT NOT NULL,
          PRIMARY KEY(site_id, source_ip)
        );
        """)
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(security_events)")}
        for name, declaration in (("severity", "TEXT NOT NULL DEFAULT 'info'"),
                                  ("rule_id", "TEXT"), ("reason", "TEXT NOT NULL DEFAULT ''")):
            if name not in columns:
                conn.execute(f"ALTER TABLE security_events ADD COLUMN {name} {declaration}")
        if not conn.execute("SELECT 1 FROM sites LIMIT 1").fetchone() and ADMIN_TOKEN:
            conn.execute("INSERT INTO sites VALUES (?,?,?,?)", ("demo", "Demo Website", _hash(ADMIN_TOKEN), _now()))
            default_policy = Policy(request_limit=int(os.getenv("DEFAULT_REQUEST_LIMIT", "120")))
            conn.execute("INSERT INTO policies VALUES (?,?)", ("demo", json.dumps(default_policy.model_dump())))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _auth(value: str, expected_hash: str) -> bool:
    return hmac.compare_digest(_hash(value), expected_hash)


def require_admin(authorization: str = Header(default=""), x_api_key: str = Header(default="")):
    supplied = authorization.removeprefix("Bearer ").strip() or x_api_key
    if not ADMIN_TOKEN or not hmac.compare_digest(supplied, ADMIN_TOKEN):
        raise HTTPException(401, "authentication required")


def site_auth(site_id: str, x_site_key: str) -> None:
    with connect_db() as conn:
        row = conn.execute("SELECT credential_hash FROM sites WHERE site_id=?", (site_id,)).fetchone()
    if not row or not _auth(x_site_key, row["credential_hash"]):
        raise HTTPException(401, "invalid site credential")


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else ""
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if any(peer_ip in network for network in TRUSTED_PROXIES):
        forwarded = request.headers.get("X-Forwarded-For", "")
        candidate = forwarded.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return peer


def get_policy(site_id: str) -> Policy:
    with connect_db() as conn:
        row = conn.execute("SELECT config FROM policies WHERE site_id=?", (site_id,)).fetchone()
    return Policy.model_validate(json.loads(row["config"])) if row else Policy()


def redis_block_key(site_id: str, source_ip: str) -> str:
    return f"block:{site_id}:{source_ip}"


def get_active_block(site_id: str, source_ip: str):
    if redis_client:
        try:
            value = redis_client.get(redis_block_key(site_id, source_ip))
            if value:
                return json.loads(value)
        except (redis.RedisError, json.JSONDecodeError):
            pass
    with connect_db() as conn:
        row = conn.execute(
            "SELECT expires_at,reason FROM ip_blocks WHERE site_id=? AND source_ip=?",
            (site_id, source_ip),
        ).fetchone()
    if row and datetime.fromisoformat(row["expires_at"]) > datetime.now(timezone.utc):
        return {"expires_at": row["expires_at"], "reason": row["reason"]}
    return None


def save_block(site_id: str, source_ip: str, expires_at: datetime, reason: str):
    payload = {"expires_at": expires_at.isoformat(), "reason": reason[:500]}
    if redis_client:
        try:
            seconds = max(1, int((expires_at - datetime.now(timezone.utc)).total_seconds()))
            redis_client.setex(redis_block_key(site_id, source_ip), seconds, json.dumps(payload))
        except redis.RedisError:
            pass
    with connect_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ip_blocks VALUES (?,?,?,?)",
            (site_id, source_ip, expires_at.isoformat(), reason[:500]),
        )


def delete_block(site_id: str, source_ip: str):
    if redis_client:
        try:
            redis_client.delete(redis_block_key(site_id, source_ip))
        except redis.RedisError:
            pass
    with connect_db() as conn:
        return conn.execute(
            "DELETE FROM ip_blocks WHERE site_id=? AND source_ip=?",
            (site_id, source_ip),
        ).rowcount


def trim(queue: deque, now: float, seconds: int):
    while queue and now - queue[0][0 if isinstance(queue[0], tuple) else 0] > seconds:
        queue.popleft()


def detect(event: Event, policy: Policy) -> list[str]:
    now, key, alerts = time.time(), (event.site_id, event.source_ip), []
    request_count = None
    if redis_client:
        try:
            request_count = int(redis_client.incr(f"requests:{event.site_id}:{event.source_ip}"))
            redis_client.expire(f"requests:{event.site_id}:{event.source_ip}", policy.window_seconds)
        except redis.RedisError:
            request_count = None
    if request_count is None:
        request_queue = windows[key]
        request_queue.append(now)
        while request_queue and now - request_queue[0] > policy.window_seconds:
            request_queue.popleft()
        request_count = len(request_queue)
    if request_count > policy.request_limit:
        alerts.append("request_flood")
    if event.failed_login:
        failed_logins[key].append(now)
        while failed_logins[key] and now - failed_logins[key][0] > policy.window_seconds:
            failed_logins[key].popleft()
        if len(failed_logins[key]) >= policy.login_limit:
            alerts.append("brute_force")
    inspected = unquote_plus(f"{event.path} {event.body}")
    if any(pattern.search(inspected) for pattern in SQLI_PATTERNS):
        alerts.append("sql_injection")
    if any(pattern.search(inspected) for pattern in XSS_PATTERNS):
        alerts.append("xss")
    if event.event_type == "port_probe" and event.destination_port:
        port_probes[key].append((now, event.destination_port))
        while port_probes[key] and now - port_probes[key][0][0] > 60:
            port_probes[key].popleft()
        if len({port for _, port in port_probes[key]}) >= 10:
            alerts.append("port_scan")
    return sorted(set(alerts))


def persist(event: Event, alerts: list[str], action: str, reason: str):
    timestamp = _now()
    with connect_db() as conn:
        conn.execute("""INSERT INTO security_events
          (timestamp,site_id,source_ip,path,method,event_type,alerts,severity,action,rule_id,reason)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
          (timestamp, event.site_id, event.source_ip, event.path, event.method.upper(), event.event_type,
           json.dumps(alerts), event.severity, action, event.rule_id, reason[:500]))
    return {"timestamp": timestamp, "site_id": event.site_id, "source_ip": event.source_ip,
            "path": event.path, "event_type": event.event_type, "alerts": alerts, "action": action,
            "severity": event.severity, "reason": reason}


@app.on_event("startup")
def startup():
    initialize_db()


@app.get("/health")
def health():
    database = "ok"
    try:
        with connect_db() as conn:
            conn.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        database = "error"
    redis_status = "disabled"
    if redis_client:
        try:
            redis_client.ping()
            redis_status = "ok"
        except redis.RedisError:
            redis_status = "unavailable"
    status = "healthy" if database == "ok" else "degraded"
    return {"status": status, "enforcement": ENFORCEMENT, "database": database, "redis": redis_status}


@app.post("/api/v1/events", status_code=201)
@app.post("/inspect", status_code=201, include_in_schema=False)
def inspect(event: Event, request: Request, x_site_key: str = Header(default="")):
    site_auth(event.site_id, x_site_key)
    policy = get_policy(event.site_id)
    source = client_ip(request) if event.source_ip == "request" else event.source_ip
    event = event.model_copy(update={"source_ip": source})
    now = datetime.now(timezone.utc)
    block = get_active_block(event.site_id, source)
    if block:
        status = 429 if "request_flood" in block["reason"] or "brute_force" in block["reason"] else 403
        return JSONResponse(persist(event, ["temporary_block"], "block", block["reason"]), status_code=status)
    alerts = detect(event, policy)
    allowed = source in policy.allowlist
    should_block = bool(alerts) and (ENFORCEMENT or policy.enforcement) and not policy.emergency_disable and not allowed
    if should_block and any(a in alerts for a in ("brute_force", "request_flood")):
        expires = now + timedelta(seconds=policy.block_duration_seconds)
        save_block(event.site_id, source, expires, ",".join(alerts))
    action = "block" if should_block else ("flag" if alerts else "allow")
    result = persist(event, alerts, action, "policy violation" if alerts else "normal request")
    return JSONResponse(result, status_code=(429 if "request_flood" in alerts or "brute_force" in alerts else 403)
                        if action == "block" else 200)


@app.get("/api/v1/gateway/check", include_in_schema=False)
def gateway_check(
    request: Request,
    site_id: str = Query(..., min_length=1, max_length=100),
    x_site_key: str = Header(default=""),
    x_original_uri: str = Header(default="/"),
    x_real_ip: str = Header(default=""),
):
    """Pre-proxy decision endpoint for the trusted local Nginx gateway."""
    site_auth(site_id, x_site_key)
    source = x_real_ip.strip() or (request.client.host if request.client else "")
    try:
        ipaddress.ip_address(source)
    except ValueError:
        raise HTTPException(400, "gateway did not provide a valid client IP")
    policy = get_policy(site_id)
    event = Event(site_id=site_id, source_ip=source, path=x_original_uri[:2048])
    block = get_active_block(site_id, source)
    if block:
        persist(event, ["temporary_block"], "block", block["reason"])
        raise HTTPException(
            403 if "request_flood" not in block["reason"] and "brute_force" not in block["reason"] else 429,
            "temporarily blocked",
            headers={"X-Security-Status": "403" if "request_flood" not in block["reason"] and "brute_force" not in block["reason"] else "429"},
        )
    alerts = detect(event, policy)
    if alerts and (ENFORCEMENT or policy.enforcement) and not policy.emergency_disable and source not in policy.allowlist:
        if any(alert in alerts for alert in ("request_flood", "brute_force")):
            expires = datetime.now(timezone.utc) + timedelta(seconds=policy.block_duration_seconds)
            save_block(site_id, source, expires, ",".join(alerts))
            persist(event, alerts, "block", "gateway policy violation")
            raise HTTPException(403, "temporarily blocked", headers={"X-Security-Status": "429"})
        persist(event, alerts, "block", "gateway policy violation")
        raise HTTPException(403, "blocked by security policy", headers={"X-Security-Status": "403"})
    if alerts:
        persist(event, alerts, "flag", "gateway policy violation")
    else:
        persist(event, [], "allow", "normal request")
    return {"allowed": True}


@app.get("/api/v1/events")
@app.get("/events", include_in_schema=False)
def events(limit: int = Query(100, ge=1, le=500), _: None = Depends(require_admin)):
    with connect_db() as conn:
        rows = conn.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(row), "alerts": json.loads(row["alerts"])} for row in rows]


@app.get("/api/v1/sites")
def sites(_: None = Depends(require_admin)):
    with connect_db() as conn:
        return [dict(row) for row in conn.execute("SELECT site_id,name,created_at FROM sites ORDER BY site_id")]


@app.post("/api/v1/sites", status_code=201)
def create_site(site: Site, _: None = Depends(require_admin)):
    with connect_db() as conn:
        if conn.execute("SELECT 1 FROM sites WHERE site_id=?", (site.site_id,)).fetchone():
            raise HTTPException(409, "site already exists")
        conn.execute("INSERT INTO sites VALUES (?,?,?,?)",
                     (site.site_id, site.name, _hash(site.credential), _now()))
        conn.execute("INSERT INTO policies VALUES (?,?)", (site.site_id, json.dumps(Policy().model_dump())))
    return {"site_id": site.site_id, "name": site.name, "credential_created": True}


@app.post("/api/v1/sites/{site_id}/rotate-credential")
def rotate_credential(site_id: str, site: Site, _: None = Depends(require_admin)):
    if site.site_id != site_id:
        raise HTTPException(400, "site identifier mismatch")
    with connect_db() as conn:
        if not conn.execute("SELECT 1 FROM sites WHERE site_id=?", (site_id,)).fetchone():
            raise HTTPException(404, "site not found")
        conn.execute("UPDATE sites SET credential_hash=? WHERE site_id=?", (_hash(site.credential), site_id))
    return {"site_id": site_id, "credential_rotated": True}


@app.put("/api/v1/sites/{site_id}/policy")
def update_policy(site_id: str, policy: Policy, _: None = Depends(require_admin)):
    with connect_db() as conn:
        if not conn.execute("SELECT 1 FROM sites WHERE site_id=?", (site_id,)).fetchone():
            raise HTTPException(404, "site not found")
        conn.execute("INSERT OR REPLACE INTO policies VALUES (?,?)", (site_id, json.dumps(policy.model_dump())))
    return policy


@app.get("/api/v1/sites/{site_id}/blocks")
def blocks(site_id: str, _: None = Depends(require_admin)):
    with connect_db() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM ip_blocks WHERE site_id=?", (site_id,))]


@app.delete("/api/v1/sites/{site_id}/blocks/{source_ip}")
def unblock(site_id: str, source_ip: str, _: None = Depends(require_admin)):
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        raise HTTPException(400, "invalid IP address")
    deleted = delete_block(site_id, source_ip)
    if not deleted:
        raise HTTPException(404, "active block not found")
    return {"site_id": site_id, "source_ip": source_ip, "unblocked": True}


# Keep command-line imports and lightweight ASGI test clients usable without a
# lifespan context; startup runs this idempotently again in normal servers.
initialize_db()
