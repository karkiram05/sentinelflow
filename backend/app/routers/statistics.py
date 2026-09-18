from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/statistics", tags=["statistics"])


@router.get("", response_model=schemas.StatisticsOut)
def get_statistics(db: Session = Depends(get_db)):
    events_analyzed = db.query(func.count(models.Event.id)).scalar() or 0
    total_alerts = db.query(func.count(models.Alert.id)).scalar() or 0

    def count_severity(sev: str) -> int:
        return db.query(func.count(models.Alert.id)).filter(models.Alert.severity == sev).scalar() or 0

    suspicious_devices = (
        db.query(func.count(models.Device.id)).filter(models.Device.alert_count > 0).scalar() or 0
    )

    top_detections_rows = (
        db.query(models.Alert.detection, func.count(models.Alert.id).label("n"))
        .group_by(models.Alert.detection)
        .order_by(func.count(models.Alert.id).desc())
        .limit(10)
        .all()
    )
    top_detections = [{"detection": row[0], "count": row[1]} for row in top_detections_rows]

    return schemas.StatisticsOut(
        events_analyzed=events_analyzed,
        total_alerts=total_alerts,
        critical_alerts=count_severity("CRITICAL"),
        high_alerts=count_severity("HIGH"),
        medium_alerts=count_severity("MEDIUM"),
        low_alerts=count_severity("LOW"),
        suspicious_devices=suspicious_devices,
        top_detections=top_detections,
    )
