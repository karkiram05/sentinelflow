from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/alerts", tags=["alerts"])

VALID_STATUSES = {"OPEN", "ACKNOWLEDGED", "CLOSED"}


@router.get("", response_model=list[schemas.AlertOut])
def list_alerts(
    limit: int = Query(50, le=500),
    offset: int = 0,
    severity: str | None = None,
    status: str | None = None,
    source_ip: str | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(models.Alert)
    if severity:
        q = q.filter(models.Alert.severity == severity.upper())
    if status:
        q = q.filter(models.Alert.status == status.upper())
    if source_ip:
        q = q.filter(models.Alert.source_ip == source_ip)
    return q.order_by(models.Alert.risk_score.desc()).offset(offset).limit(limit).all()


@router.get("/{alert_id}", response_model=schemas.AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}", response_model=schemas.AlertOut)
def update_alert_status(alert_id: int, status: str, db: Session = Depends(get_db)):
    status = status.upper()
    if status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(VALID_STATUSES)}")
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = status
    db.commit()
    db.refresh(alert)
    return alert
