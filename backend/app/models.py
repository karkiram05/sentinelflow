import datetime as dt

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    JSON,
)
from sqlalchemy.orm import relationship

from app.database import Base


class Device(Base):
    """A network endpoint SentinelFlow has observed traffic from or to."""

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    first_seen = Column(DateTime, default=dt.datetime.utcnow)
    last_seen = Column(DateTime, default=dt.datetime.utcnow)
    event_count = Column(Integer, default=0)
    alert_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)

    events = relationship("Event", back_populates="device")


class Event(Base):
    """A single ingested network flow record (a row of telemetry)."""

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=dt.datetime.utcnow, index=True)
    source_ip = Column(String, index=True)
    destination_ip = Column(String, index=True)
    protocol = Column(String)
    destination_port = Column(Integer, nullable=True)
    service = Column(String, nullable=True)
    flag = Column(String, nullable=True)
    duration = Column(Float, default=0.0)
    src_bytes = Column(Integer, default=0)
    dst_bytes = Column(Integer, default=0)

    # Raw feature vector used for detection, stored for traceability/audit.
    features = Column(JSON, default=dict)

    # Ground-truth label, only populated when ingesting a labeled dataset
    # (used for evaluation, never used by the detection engine itself).
    ground_truth_label = Column(String, nullable=True)

    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    device = relationship("Device", back_populates="events")

    alert = relationship("Alert", back_populates="event", uselist=False)


class Alert(Base):
    """A security alert produced by the detection engine for one event."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_code = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow, index=True)

    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
    event = relationship("Event", back_populates="alert")

    source_ip = Column(String, index=True)
    destination_ip = Column(String, index=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)

    detection = Column(String, nullable=False)  # human-readable detection name
    detection_source = Column(String, nullable=False)  # "rule" | "ml" | "rule+ml"
    mitre_technique = Column(String, nullable=True)
    mitre_technique_name = Column(String, nullable=True)

    confidence = Column(Float, default=0.0)
    risk_score = Column(Float, default=0.0)
    severity = Column(String, default="LOW")  # LOW | MEDIUM | HIGH | CRITICAL
    status = Column(String, default="OPEN")  # OPEN | ACKNOWLEDGED | CLOSED
