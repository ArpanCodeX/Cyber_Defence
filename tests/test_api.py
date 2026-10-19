import os
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

os.environ["CYBER_API_KEY"] = "test-admin-token-1234567890"
os.environ["CYBER_ADMIN_TOKEN"] = "test-admin-token-1234567890"
os.environ["CYBER_DB_PATH"] = "/tmp/universal-security-test.db"
try:
    os.remove(os.environ["CYBER_DB_PATH"])
except FileNotFoundError:
    pass
from app.main import app

client = TestClient(app)
KEY = "test-admin-token-1234567890"

def event(**kwargs):
    value = {"site_id":"demo","source_ip":"198.51.100.10","path":"/","method":"GET"}
    value.update(kwargs)
    return client.post("/api/v1/events", headers={"X-Site-Key":KEY}, json=value)

def test_normal_request_persists():
    response = event()
    assert response.status_code == 200 and response.json()["action"] == "allow"

def test_attack_signature_detection():
    response = event(path="/search?q=union%20select", body="<script>alert(1)</script>")
    assert response.status_code == 200
    assert set(response.json()["alerts"]) == {"sql_injection", "xss"}

def test_authentication_and_tenant_isolation():
    assert client.get("/api/v1/events").status_code == 401
    assert client.get("/api/v1/events", headers={"Authorization":"Bearer wrong"}).status_code == 401
    assert client.get("/api/v1/events", headers={"Authorization":f"Bearer {KEY}"}).status_code == 200
    assert event(site_id="unknown").status_code == 401

def test_rate_limit_detection_only_does_not_block():
    for _ in range(121):
        response = event(source_ip="198.51.100.20")
    assert response.status_code == 200
    assert "request_flood" in response.json()["alerts"]

def test_forwarded_header_is_not_an_event_identity():
    response = client.post("/api/v1/events", headers={"X-Site-Key":KEY, "X-Forwarded-For":"10.0.0.1"},
                           json={"site_id":"demo","source_ip":"198.51.100.30"})
    assert response.status_code == 200
    assert response.json()["source_ip"] == "198.51.100.30"

def test_enforcement_creates_temporary_rate_block():
    policy = {"request_limit": 1, "window_seconds": 60, "login_limit": 5,
              "block_duration_seconds": 10, "enforcement": True,
              "allowlist": [], "emergency_disable": False}
    updated = client.put("/api/v1/sites/demo/policy",
                         headers={"Authorization":f"Bearer {KEY}"}, json=policy)
    assert updated.status_code == 200
    source = "198.51.100.99"
    assert event(source_ip=source).status_code == 200
    assert event(source_ip=source).status_code == 429
    assert event(source_ip=source).status_code == 429

def test_health_reports_database_and_redis_mode():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["database"] == "ok"
    assert response.json()["redis"] in {"disabled", "ok", "unavailable"}

def test_malformed_and_oversized_events_are_rejected():
    headers = {"X-Site-Key": KEY}
    assert client.post("/api/v1/events", headers=headers, json={"site_id":"demo","source_ip":"not-an-ip"}).status_code == 422
    assert client.post("/api/v1/events", headers=headers,
                       json={"site_id":"demo","source_ip":"198.51.100.60","body":"x"*10001}).status_code == 422

def test_allowlist_and_emergency_disable_prevent_enforcement():
    policy = {"request_limit": 1, "window_seconds": 60, "login_limit": 5,
              "block_duration_seconds": 10, "enforcement": True,
              "allowlist": ["198.51.100.70"], "emergency_disable": False}
    assert client.put("/api/v1/sites/demo/policy", headers={"Authorization":f"Bearer {KEY}"}, json=policy).status_code == 200
    assert event(source_ip="198.51.100.70").status_code == 200
    assert event(source_ip="198.51.100.70").status_code == 200
    policy["allowlist"] = []
    policy["emergency_disable"] = True
    assert client.put("/api/v1/sites/demo/policy", headers={"Authorization":f"Bearer {KEY}"}, json=policy).status_code == 200
    assert event(source_ip="198.51.100.71").status_code == 200

def test_brute_force_blocks_and_expired_block_allows():
    policy = {"request_limit": 100, "window_seconds": 60, "login_limit": 2,
              "block_duration_seconds": 10, "enforcement": True,
              "allowlist": [], "emergency_disable": False}
    assert client.put("/api/v1/sites/demo/policy", headers={"Authorization":f"Bearer {KEY}"}, json=policy).status_code == 200
    source = "198.51.100.80"
    assert event(source_ip=source, failed_login=True).status_code == 200
    assert event(source_ip=source, failed_login=True).status_code == 429
    from app.main import connect_db
    with connect_db() as conn:
        conn.execute("UPDATE ip_blocks SET expires_at=? WHERE site_id='demo' AND source_ip=?",
                     ((datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat(), source))
    assert event(source_ip=source).status_code == 200

def test_gateway_decision_blocks_before_backend_path():
    policy = {"request_limit": 100, "window_seconds": 60, "login_limit": 5,
              "block_duration_seconds": 10, "enforcement": True,
              "allowlist": [], "emergency_disable": False}
    assert client.put("/api/v1/sites/demo/policy", headers={"Authorization":f"Bearer {KEY}"}, json=policy).status_code == 200
    response = client.get(
        "/api/v1/gateway/check?site_id=demo",
        headers={"X-Site-Key": KEY, "X-Real-IP": "198.51.100.90",
                 "X-Original-URI": "/search?q=union%20select"},
    )
    assert response.status_code == 403

def test_gateway_rate_limit_sets_429_status_for_nginx_mapping():
    policy = {"request_limit": 1, "window_seconds": 60, "login_limit": 5,
              "block_duration_seconds": 10, "enforcement": True,
              "allowlist": [], "emergency_disable": False}
    assert client.put("/api/v1/sites/demo/policy", headers={"Authorization":f"Bearer {KEY}"}, json=policy).status_code == 200
    source = "198.51.100.91"
    first = client.get("/api/v1/gateway/check?site_id=demo",
                       headers={"X-Site-Key":KEY, "X-Real-IP":source, "X-Original-URI":"/"})
    second = client.get("/api/v1/gateway/check?site_id=demo",
                        headers={"X-Site-Key":KEY, "X-Real-IP":source, "X-Original-URI":"/"})
    assert first.status_code == 200
    assert second.status_code == 403
    assert second.headers["x-security-status"] == "429"
