"""Shared ingestion path: turns one event payload into DB rows and,
if the detection engine fires, an Alert row. Used by both the /events API
endpoint and scripts/load_dataset.py, so the API and the offline evaluation
script can never drift apart.
"""
import uuid

from sqlalchemy.orm import Session

from app import models
from app.detection import risk
from app.detection.engine import evaluate_event
from app.state import detection_state


def get_or_create_device(db: Session, ip_address: str) -> models.Device:
    device = db.query(models.Device).filter(models.Device.ip_address == ip_address).first()
    if device is None:
        device = models.Device(ip_address=ip_address)
        db.add(device)
        db.flush()
    return device


def record_event(db: Session, event_in: dict) -> tuple[models.Event, models.Alert | None]:
    source_ip = event_in["source_ip"]
    destination_ip = event_in["destination_ip"]

    src_device = get_or_create_device(db, source_ip)

    event = models.Event(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=event_in.get("protocol"),
        destination_port=event_in.get("destination_port"),
        service=event_in.get("service"),
        flag=event_in.get("flag"),
        duration=event_in.get("duration", 0.0),
        src_bytes=event_in.get("src_bytes", 0),
        dst_bytes=event_in.get("dst_bytes", 0),
        features=event_in.get("features", {}),
        ground_truth_label=event_in.get("ground_truth_label"),
        device_id=src_device.id,
    )
    db.add(event)
    db.flush()

    src_device.event_count += 1
    src_device.last_seen = event.timestamp

    alert = None
    result = evaluate_event(event.features, detection_state.anomaly_detector)
    if result is not None:
        # alert_count at this point is the number of PRIOR alerts from this
        # source (it's incremented below, after this read) -- that's the
        # repeat-offender signal risk.apply_repeat_offender_boost wants.
        boosted_score = risk.apply_repeat_offender_boost(result.risk_score, src_device.alert_count)
        severity = risk.severity_band(boosted_score)

        alert = models.Alert(
            alert_code=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            event_id=event.id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=event.destination_port,
            protocol=event.protocol,
            detection=result.detection,
            detection_source=result.detection_source,
            mitre_technique=result.mitre_technique,
            mitre_technique_name=result.mitre_technique_name,
            confidence=result.confidence,
            risk_score=boosted_score,
            severity=severity,
            status="OPEN",
        )
        db.add(alert)
        src_device.alert_count += 1
        src_device.risk_score = max(src_device.risk_score, boosted_score)

    db.commit()
    db.refresh(event)
    if alert is not None:
        db.refresh(alert)
    return event, alert
