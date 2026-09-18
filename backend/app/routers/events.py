from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.ingest import record_event

router = APIRouter(prefix="/events", tags=["events"])


@router.post("", response_model=schemas.EventOut, status_code=201)
def create_event(event_in: schemas.EventIn, db: Session = Depends(get_db)):
    event, _alert = record_event(db, event_in.model_dump())
    return event


@router.get("", response_model=list[schemas.EventOut])
def list_events(
    limit: int = Query(50, le=500),
    offset: int = 0,
    source_ip: str | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(models.Event)
    if source_ip:
        q = q.filter(models.Event.source_ip == source_ip)
    return q.order_by(models.Event.id.desc()).offset(offset).limit(limit).all()
