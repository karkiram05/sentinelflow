from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=list[schemas.DeviceOut])
def list_devices(
    limit: int = Query(50, le=500),
    offset: int = 0,
    min_risk_score: float = 0.0,
    db: Session = Depends(get_db),
):
    q = db.query(models.Device).filter(models.Device.risk_score >= min_risk_score)
    return q.order_by(models.Device.risk_score.desc()).offset(offset).limit(limit).all()


@router.get("/{ip_address}", response_model=schemas.DeviceOut)
def get_device(ip_address: str, db: Session = Depends(get_db)):
    device = db.query(models.Device).filter(models.Device.ip_address == ip_address).first()
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    return device
