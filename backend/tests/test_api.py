from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_benign_event_produces_no_alert():
    response = client.post("/events", json={
        "source_ip": "10.1.1.1",
        "destination_ip": "10.1.1.2",
        "protocol": "tcp",
        "features": {"flag": "SF", "src_bytes": 100, "dst_bytes": 100, "count": 1},
    })
    assert response.status_code == 201
    body = response.json()
    assert body["source_ip"] == "10.1.1.1"

    alerts = client.get("/alerts", params={"source_ip": "10.1.1.1"}).json()
    assert alerts == []


def test_create_malicious_event_produces_alert():
    response = client.post("/events", json={
        "source_ip": "10.2.2.2",
        "destination_ip": "10.2.2.3",
        "protocol": "tcp",
        "destination_port": 22,
        "features": {"land": 1},
    })
    assert response.status_code == 201

    alerts = client.get("/alerts", params={"source_ip": "10.2.2.2"}).json()
    assert len(alerts) == 1
    assert alerts[0]["detection"] == "Land attack (spoofed src=dst)"
    assert alerts[0]["mitre_technique"] == "T1498"
    assert alerts[0]["status"] == "OPEN"


def test_alert_status_update():
    client.post("/events", json={
        "source_ip": "10.3.3.3",
        "destination_ip": "10.3.3.4",
        "protocol": "tcp",
        "features": {"root_shell": 1},
    })
    alerts = client.get("/alerts", params={"source_ip": "10.3.3.3"}).json()
    alert_id = alerts[0]["id"]

    response = client.patch(f"/alerts/{alert_id}", params={"status": "acknowledged"})
    assert response.status_code == 200
    assert response.json()["status"] == "ACKNOWLEDGED"


def test_alert_status_update_rejects_invalid_status():
    client.post("/events", json={
        "source_ip": "10.3.3.5",
        "destination_ip": "10.3.3.6",
        "protocol": "tcp",
        "features": {"root_shell": 1},
    })
    alerts = client.get("/alerts", params={"source_ip": "10.3.3.5"}).json()
    alert_id = alerts[0]["id"]

    response = client.patch(f"/alerts/{alert_id}", params={"status": "not-a-status"})
    assert response.status_code == 400


def test_device_tracking_updates_risk_score():
    client.post("/events", json={
        "source_ip": "10.4.4.4",
        "destination_ip": "10.4.4.5",
        "protocol": "tcp",
        "features": {"root_shell": 1},
    })
    device = client.get("/devices/10.4.4.4").json()
    assert device["event_count"] == 1
    assert device["alert_count"] == 1
    assert device["risk_score"] > 0


def test_statistics_endpoint_reflects_ingested_alerts():
    client.post("/events", json={
        "source_ip": "10.5.5.5",
        "destination_ip": "10.5.5.6",
        "protocol": "tcp",
        "features": {"land": 1},
    })
    stats = client.get("/statistics").json()
    assert stats["events_analyzed"] >= 1
    assert stats["total_alerts"] >= 1


def test_device_not_found_returns_404():
    response = client.get("/devices/1.2.3.4")
    assert response.status_code == 404


def test_alert_not_found_returns_404():
    response = client.get("/alerts/999999")
    assert response.status_code == 404
