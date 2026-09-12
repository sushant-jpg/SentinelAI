import json
from datetime import datetime
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from pydantic import ValidationError
from sqlalchemy import select, func, or_
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.core.config import get_settings
from app.core.security import current_user, analyst, admin, ingest_identity, audit, rate_limit, utc
from app.models.entities import (
    User,
    Event,
    Alert,
    Asset,
    DetectionRule,
    MitreTechnique,
    AnalystNote,
    Incident,
    IncidentAlert,
    IncidentTimeline,
    AuditLog,
    AuthSession,
    now,
)
from app.schemas.inputs import EventBatch, AlertPatch, NoteInput, IncidentCreate, IncidentPatch, UserPatch, RulePatch, AssetPatch, Severity, Status
from app.services.ingestion import ingest
from app.services.analytics import analytics
from app.services.demo import demo_events
from app.integrations.adapters import wazuh, suricata
from app.ai.explainer import explain
from app.api.auth import public_user

router = APIRouter()


def serialize(model):
    return jsonable_encoder({c.name: getattr(model, c.name) for c in model.__table__.columns})


def get_or_404(db, model, key):
    row = db.get(model, key)
    if row is None:
        raise HTTPException(404, "Record not found")
    return row


def page_result(db, query, page, page_size):
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery()))
    items = db.scalars(query.offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [serialize(item) for item in items], "total": total, "page": page, "page_size": page_size}


def check_assignee(db, identifier):
    if identifier:
        user = db.get(User, identifier)
        if not user or not user.active or user.role not in ("analyst", "admin"):
            raise HTTPException(422, "Assignee must be an active analyst or admin")


@router.post("/events", status_code=201, tags=["Events"])
def events_ingest(body: EventBatch, request: Request, db: Session = Depends(get_db), identity: str = Depends(ingest_identity)):
    result = ingest(db, body.events)
    audit(db, request, identity, "events.ingest", str(result["accepted"]))
    db.commit()
    return result


@router.get("/events", tags=["Events"])
def events_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    event_id: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = select(Event).order_by(Event.timestamp.desc())
    if event_id:
        query = query.where(Event.event_id == event_id)
    return page_result(db, query, page, page_size)


@router.post("/events/import/{source}", status_code=201, tags=["Integrations"])
async def import_events(source: Literal["wazuh", "suricata"], request: Request, db: Session = Depends(get_db), identity: str = Depends(ingest_identity)):
    raw = await request.body()
    try:
        text = raw.decode("utf-8")
        try:
            payload = json.loads(text)
            payloads = payload if isinstance(payload, list) else [payload]
        except json.JSONDecodeError:
            payloads = [json.loads(line) for line in text.splitlines() if line.strip()]
        if not 1 <= len(payloads) <= 500 or not all(isinstance(p, dict) for p in payloads):
            raise ValueError("Provide 1–500 JSON objects")
        adapter = wazuh if source == "wazuh" else suricata
        events = [adapter(p) for p in payloads]
    except (ValueError, KeyError, TypeError, AttributeError, ValidationError, UnicodeDecodeError):
        raise HTTPException(422, "Invalid sensor payload. See integration documentation.") from None
    result = ingest(db, events, origin=source)
    audit(db, request, identity, "events.import", source)
    db.commit()
    return result


@router.post("/events/demo", status_code=201, tags=["Events"])
def demo(request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    if not get_settings().demo_mode:
        raise HTTPException(403, "Demo mode is disabled")
    rate_limit(db, "demo:" + user.id, 3)
    result = ingest(db, demo_events(), origin="demo")
    audit(db, request, user.email, "events.demo", str(result["accepted"]))
    db.commit()
    return result


@router.get("/alerts", tags=["Alerts"])
def alerts_list(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Severity | None = None,
    status: Status | None = None,
    q: str = Query("", max_length=200),
    ip: str | None = None,
    host: str | None = None,
    username: str | None = None,
    event_type: str | None = None,
    technique: str | None = None,
    min_risk: int = Query(0, ge=0, le=100),
    max_risk: int = Query(100, ge=0, le=100),
    start: datetime | None = None,
    end: datetime | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if min_risk > max_risk or (start and end and utc(start) > utc(end)):
        raise HTTPException(422, "Invalid filter range")
    query = select(Alert).where(Alert.risk_score >= min_risk, Alert.risk_score <= max_risk)
    for field, value in [
        (Alert.severity, severity),
        (Alert.status, status),
        (Alert.source_ip, ip),
        (Alert.affected_host, host),
        (Alert.username, username),
        (Alert.event_type, event_type),
        (Alert.technique_id, technique),
    ]:
        if value:
            query = query.where(field == value)
    if q:
        query = query.where(
            or_(*(field.icontains(q, autoescape=True) for field in [Alert.title, Alert.source_ip, Alert.affected_host, Alert.username, Alert.technique_id]))
        )
    if start:
        query = query.where(Alert.timestamp >= start)
    if end:
        query = query.where(Alert.timestamp <= end)
    return page_result(db, query.order_by(Alert.timestamp.desc(), Alert.alert_id), page, page_size)


@router.get("/alerts/{alert_id}", tags=["Alerts"])
def alert_detail(alert_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    alert = get_or_404(db, Alert, alert_id)
    result = serialize(alert)
    result["notes"] = [serialize(n) for n in db.scalars(select(AnalystNote).where(AnalystNote.alert_id == alert_id).order_by(AnalystNote.timestamp))]
    result["technique"] = serialize(db.get(MitreTechnique, alert.technique_id))
    result["events"] = [
        serialize(e) for e in db.scalars(select(Event).where(Event.event_id.in_(alert.evidence["event_ids"])).order_by(Event.timestamp).limit(100))
    ]
    return result


@router.patch("/alerts/{alert_id}", tags=["Alerts"])
def update_alert(alert_id: str, body: AlertPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    alert = get_or_404(db, Alert, alert_id)
    data = body.model_dump(exclude_unset=True)
    if "status" in data and data["status"] is None:
        raise HTTPException(422, "Status cannot be null")
    check_assignee(db, body.assigned_to)
    for key, value in data.items():
        setattr(alert, key, value)
        audit(db, request, user.email, "alert." + key, alert_id)
    db.commit()
    return serialize(alert)


@router.post("/alerts/{alert_id}/notes", status_code=201, tags=["Alerts"])
def add_note(alert_id: str, body: NoteInput, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    get_or_404(db, Alert, alert_id)
    note = AnalystNote(alert_id=alert_id, user_id=user.id, text=body.text)
    db.add(note)
    audit(db, request, user.email, "alert.note", alert_id)
    db.commit()
    return serialize(note)


@router.get("/incidents", tags=["Incidents"])
def incidents_list(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), user: User = Depends(current_user)):
    return page_result(db, select(Incident).order_by(Incident.updated_at.desc()), page, page_size)


@router.post("/incidents", status_code=201, tags=["Incidents"])
def create_incident(body: IncidentCreate, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    alerts = [get_or_404(db, Alert, key) for key in set(body.related_alerts)]
    check_assignee(db, body.assigned_analyst)
    incident = Incident(
        title=body.title,
        description=body.description,
        severity=max(alerts, key=lambda a: a.risk_score).severity,
        assigned_analyst=body.assigned_analyst,
        affected_assets=sorted({a.affected_host for a in alerts}),
    )
    db.add(incident)
    db.flush()
    for alert in alerts:
        db.add(IncidentAlert(incident_id=incident.incident_id, alert_id=alert.alert_id))
    db.add(IncidentTimeline(incident_id=incident.incident_id, user_id=user.id, action="Created", note=f"Linked {len(alerts)} alerts."))
    audit(db, request, user.email, "incident.create", incident.incident_id)
    db.commit()
    return serialize(incident)


@router.get("/incidents/{incident_id}", tags=["Incidents"])
def incident_detail(incident_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    incident = get_or_404(db, Incident, incident_id)
    result = serialize(incident)
    result["related_alerts"] = [serialize(a) for a in db.scalars(select(Alert).join(IncidentAlert).where(IncidentAlert.incident_id == incident_id))]
    result["timeline"] = [
        serialize(t) for t in db.scalars(select(IncidentTimeline).where(IncidentTimeline.incident_id == incident_id).order_by(IncidentTimeline.timestamp))
    ]
    return result


@router.patch("/incidents/{incident_id}", tags=["Incidents"])
def update_incident(incident_id: str, body: IncidentPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(analyst)):
    incident = get_or_404(db, Incident, incident_id)
    data = body.model_dump(exclude_unset=True)
    if any(key in data and data[key] is None for key in ("status", "resolution", "note")):
        raise HTTPException(422, "Status, resolution and note cannot be null")
    if body.status == "Resolved" and not (body.resolution or incident.resolution).strip():
        raise HTTPException(422, "Resolution is required to close an incident")
    if (
        incident.status == "Resolved"
        and body.resolution is not None
        and not body.resolution.strip()
        and body.status not in ("New", "Investigating", "False Positive")
    ):
        raise HTTPException(422, "Resolved incidents require a resolution")
    check_assignee(db, body.assigned_analyst)
    for key, value in data.items():
        if key != "note":
            setattr(incident, key, value)
    incident.updated_at = now()
    if body.status:
        incident.resolved_at = now() if body.status == "Resolved" else None
    db.add(
        IncidentTimeline(
            incident_id=incident_id,
            user_id=user.id,
            action=body.status or "Updated",
            note=body.note or body.resolution or "Assignment or incident details updated.",
        )
    )
    audit(db, request, user.email, "incident." + (body.status or "update").lower(), incident_id)
    db.commit()
    return serialize(incident)


@router.get("/assets", tags=["Assets"])
def assets_list(db: Session = Depends(get_db), user: User = Depends(current_user)):
    items = []
    for asset in db.scalars(select(Asset).order_by(Asset.hostname)):
        count, risk = db.execute(
            select(func.count(), func.max(Alert.risk_score)).where(Alert.affected_host == asset.hostname, Alert.status.in_(["New", "Investigating"]))
        ).one()
        items.append(
            {
                **serialize(asset),
                "number_of_alerts": count,
                "risk_score": risk or 0,
                "agent_status": "active" if (now() - utc(asset.last_seen)).total_seconds() < 900 else "stale",
            }
        )
    return {"items": items}


@router.patch("/assets/{asset_id}", tags=["Assets"])
def update_asset(asset_id: str, body: AssetPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    asset = get_or_404(db, Asset, asset_id)
    asset.operating_system, asset.sensitivity = body.operating_system, body.sensitivity
    audit(db, request, user.email, "asset.update", asset_id)
    db.commit()
    return serialize(asset)


@router.get("/rules", tags=["Rules"])
def rules_list(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return {"items": [serialize(r) for r in db.scalars(select(DetectionRule).order_by(DetectionRule.title))]}


@router.patch("/rules/{rule_id}", tags=["Rules"])
def update_rule(rule_id: str, body: RulePatch, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    rule = get_or_404(db, DetectionRule, rule_id)
    rule.enabled = body.enabled
    audit(db, request, user.email, "rule.enable" if body.enabled else "rule.disable", rule_id)
    db.commit()
    return serialize(rule)


@router.get("/analytics", tags=["Analytics"])
def metrics(days: int = Query(7, ge=1, le=90), db: Session = Depends(get_db), user: User = Depends(current_user)):
    return analytics(db, days)


@router.post("/ai/alerts/{alert_id}", tags=["AI"])
def ai_analysis(alert_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(current_user)):
    alert = get_or_404(db, Alert, alert_id)
    rate_limit(db, "ai:" + user.id, 30)
    result = explain(serialize(alert))
    audit(db, request, user.email, "ai.explain", alert_id)
    db.commit()
    return result


@router.get("/users/assignable", tags=["Users"])
def assignable(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return {"items": [{"id": u.id, "name": u.name} for u in db.scalars(select(User).where(User.active.is_(True), User.role.in_(["admin", "analyst"])))]}


@router.get("/users", tags=["Users"])
def users_list(db: Session = Depends(get_db), user: User = Depends(admin)):
    return {"items": [public_user(u) for u in db.scalars(select(User).order_by(User.created_at.desc()))]}


@router.patch("/users/{user_id}", tags=["Users"])
def update_user(user_id: str, body: UserPatch, request: Request, db: Session = Depends(get_db), user: User = Depends(admin)):
    target = get_or_404(db, User, user_id)
    if target.id == user.id:
        raise HTTPException(422, "You cannot change your own role or active state")
    for key, value in body.model_dump(exclude_unset=True).items():
        if value is None:
            raise HTTPException(422, "Role and active state cannot be null")
        setattr(target, key, value)
    for session in db.scalars(select(AuthSession).where(AuthSession.user_id == user_id)):
        session.revoked = True
    audit(db, request, user.email, "user.permissions", user_id)
    db.commit()
    return public_user(target)


@router.get("/audit", tags=["Audit"])
def audit_list(page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100), db: Session = Depends(get_db), user: User = Depends(admin)):
    return page_result(db, select(AuditLog).order_by(AuditLog.timestamp.desc()), page, page_size)


@router.get("/settings", tags=["Settings"])
def settings(user: User = Depends(current_user)):
    cfg = get_settings()
    return {
        "demo_mode": cfg.demo_mode,
        "registration_enabled": cfg.registration_enabled,
        "environment": cfg.environment,
        "ai_provider": cfg.ai_provider,
        "integrations": {"wazuh": "Import API available", "suricata": "EVE JSON import available"},
        "access_token_minutes": 15,
        "rule_format": "Sigma subset + SentinelAI correlations",
    }
