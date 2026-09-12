from hashlib import sha256
from sqlalchemy import select, text
from app.core.security import utc
from app.models.entities import Event, Asset
from app.detection.engine import detect


def ingest(db, events, origin="api"):
    accepted, duplicates, alert_ids = 0, 0, []
    # Serialize batches on PostgreSQL so correlation and replay suppression are atomic.
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(7310942)"))
    for item in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
        if db.get(Event, item.event_id):
            duplicates += 1
            continue
        event = Event(**item.model_dump(), origin=origin)
        db.add(event)
        asset = db.scalar(select(Asset).where(Asset.hostname == event.hostname))
        if not asset:
            asset = Asset(hostname=event.hostname, ip_address=event.destination_ip, last_seen=event.timestamp)
            db.add(asset)
        elif utc(event.timestamp) >= utc(asset.last_seen):
            asset.last_seen = event.timestamp
            asset.ip_address = event.destination_ip or asset.ip_address
        db.flush()
        alert_ids.extend(alert.alert_id for alert in detect(db, event))
        accepted += 1
    return {"accepted": accepted, "duplicates": duplicates, "alerts_created": len(alert_ids), "alert_ids": alert_ids}


def stable_id(payload: str) -> str:
    return sha256(payload.encode()).hexdigest()
