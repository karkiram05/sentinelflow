import datetime as dt
import ipaddress
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Upper bounds on attacker-controlled input. The features dict is open by
# design (new detection features don't need an API change), so it is
# bounded instead: number of keys, key length, and scalar-only values.
MAX_FEATURES = 64
MAX_FEATURE_KEY_LEN = 64
MAX_FEATURE_STR_LEN = 64


def _validate_ip(value: str) -> str:
    """Reject anything that isn't a real IPv4/IPv6 address.

    A network flow's address field isn't free text, and these values flow
    straight through to the dashboard (frontend/index.html), so accepting
    arbitrary strings here is an XSS vector, not just a data-quality issue.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"{value!r} is not a valid IPv4/IPv6 address") from exc
    return value


class EventIn(BaseModel):
    """Payload for submitting a single network flow record to /events."""

    source_ip: str = Field(max_length=45)
    destination_ip: str = Field(max_length=45)
    protocol: str = Field(min_length=1, max_length=16)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    service: Optional[str] = Field(default=None, max_length=64)
    flag: Optional[str] = Field(default=None, max_length=16)
    duration: float = Field(default=0.0, ge=0, le=1e9)
    src_bytes: int = Field(default=0, ge=0, le=10**15)
    dst_bytes: int = Field(default=0, ge=0, le=10**15)
    features: dict = {}
    ground_truth_label: Optional[str] = Field(default=None, max_length=64)

    @field_validator("features")
    @classmethod
    def _features_must_be_bounded(cls, value: dict) -> dict:
        if len(value) > MAX_FEATURES:
            raise ValueError(f"features may hold at most {MAX_FEATURES} keys")
        for key, item in value.items():
            if len(key) > MAX_FEATURE_KEY_LEN:
                raise ValueError(f"feature name longer than {MAX_FEATURE_KEY_LEN} characters")
            if item is not None and not isinstance(item, (int, float, str, bool)):
                raise ValueError(f"feature {key!r} must be a number, string, boolean or null")
            if isinstance(item, str) and len(item) > MAX_FEATURE_STR_LEN:
                raise ValueError(f"feature {key!r} longer than {MAX_FEATURE_STR_LEN} characters")
        return value

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _ip_must_be_valid(cls, value: str) -> str:
        return _validate_ip(value)


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
