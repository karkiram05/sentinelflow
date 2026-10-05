"""Tests for the API hardening in app/security.py and the input bounds in
app/schemas.py."""
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.security import write_limiter

AUTHED = {"X-API-Key": "test-api-key"}
EVENT = {"source_ip": "10.9.9.9", "destination_ip": "10.9.9.10", "protocol": "tcp"}

client = TestClient(app)


def test_write_without_api_key_is_rejected():
    response = client.post("/events", json=EVENT)
    assert response.status_code == 401
    assert client.get("/events").json() == []


def test_write_with_wrong_api_key_is_rejected():
    response = client.post("/events", json=EVENT, headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_alert_status_change_needs_api_key():
    client.post("/events", json={**EVENT, "features": {"land": 1}}, headers=AUTHED)
    alert_id = client.get("/alerts").json()[0]["id"]
    response = client.patch(f"/alerts/{alert_id}", params={"status": "closed"})
    assert response.status_code == 401
    assert client.get(f"/alerts/{alert_id}").json()["status"] == "OPEN"


def test_writes_fail_closed_when_no_key_is_configured(monkeypatch):
    monkeypatch.setattr(settings, "API_KEY", "")
    response = client.post("/events", json=EVENT, headers=AUTHED)
    assert response.status_code == 503


def test_reads_stay_open_for_the_dashboard():
    assert client.get("/statistics").status_code == 200
    assert client.get("/alerts").status_code == 200


def test_security_headers_present():
    response = client.get("/health")
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self';" in csp
    assert "frame-ancestors 'none'" in csp
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_dashboard_has_no_inline_script():
    html = client.get("/").text
    assert '<script src="/static/app.js"></script>' in html
    assert "<script>" not in html
    assert client.get("/static/app.js").status_code == 200


def test_write_rate_limit_returns_429(monkeypatch):
    monkeypatch.setattr(write_limiter, "limit", 3)
    codes = [client.post("/events", json=EVENT, headers=AUTHED).status_code for _ in range(4)]
    assert codes == [201, 201, 201, 429]
    limited = client.post("/events", json=EVENT, headers=AUTHED)
    assert int(limited.headers["Retry-After"]) >= 1
    assert "Content-Security-Policy" in limited.headers


def test_oversized_body_is_rejected():
    padding = {f"k{i}": "x" * 60 for i in range(400)}
    response = client.post("/events", json={**EVENT, "features": padding}, headers=AUTHED)
    assert response.status_code == 413
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_features_dict_is_bounded():
    too_many = {f"f{i}": 1 for i in range(65)}
    assert client.post("/events", json={**EVENT, "features": too_many}, headers=AUTHED).status_code == 422
    nested = {"count": {"a": 1}}
    assert client.post("/events", json={**EVENT, "features": nested}, headers=AUTHED).status_code == 422


def test_numeric_fields_are_bounded():
    assert client.post("/events", json={**EVENT, "destination_port": 70000}, headers=AUTHED).status_code == 422
    assert client.post("/events", json={**EVENT, "src_bytes": -1}, headers=AUTHED).status_code == 422


def test_pagination_rejects_negative_offset():
    assert client.get("/alerts", params={"offset": -1}).status_code == 422
