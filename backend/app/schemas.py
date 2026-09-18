import datetime as dt
from typing import Optional

from pydantic import BaseModel, ConfigDict


class EventIn(BaseModel):
    """Payload for submitting a single network flow record to /events."""

    source_ip: str
    destination_ip: str
    protocol: str
    destination_port: Optional[int] = None
    service: Optional[str] = None
    flag: Optional[str] = None
    duration: float = 0.0
    src_bytes: int = 0
    dst_bytes: int = 0
    features: dict = {}
    ground_truth_label: Optional[str] = None


class EventOut(EventIn):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: dt.datetime


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_code: str
    created_at: dt.datetime
    event_id: int
    source_ip: str
    destination_ip: str
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    detection: str
    detection_source: str
    mitre_technique: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    confidence: float
    risk_score: float
    severity: str
    status: str


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    first_seen: dt.datetime
    last_seen: dt.datetime
    event_count: int
    alert_count: int
    risk_score: float


class StatisticsOut(BaseModel):
    events_analyzed: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    suspicious_devices: int
    top_detections: list[dict]
