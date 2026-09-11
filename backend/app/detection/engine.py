from datetime import timedelta
from hashlib import sha256
from sqlalchemy import select, func
from app.core.security import utc
from app.models.entities import Event, Alert, Asset, DetectionRule, Incident, IncidentAlert
from app.detection.rules import matches
from app.detection.risk import score_risk


def detect(db, event: Event) -> list[Alert]:
    generated = []
    rules = db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all()
    for stored in rules:
        rule, options = stored.definition, stored.definition['sentinel']
        if not matches(rule, event):
            continue
        kind, threshold = options['kind'], options['threshold']
        since = event.timestamp - timedelta(seconds=options['window_seconds'])
        if kind != 'single' and not event.source_ip:
            continue
        query = select(Event).where(Event.timestamp >= since, Event.timestamp <= event.timestamp, Event.hostname == event.hostname)
        if kind != 'unusual_source':
            query = query.where(Event.source_ip == event.source_ip)
        # Queries include stable persisted history; batch order is normalized at ingestion.
        history = db.scalars(query.order_by(Event.timestamp, Event.event_id)).all() if kind != 'single' else [event]
        evidence = [item for item in history if matches(rule, item)]
        if kind == 'success_after_failures':
            if not event.username:
                continue
            evidence = [item for item in history if item.event_type in ('ssh_failed', 'login_failed') and item.username == event.username and utc(item.timestamp) <= utc(event.timestamp)]
        if kind == 'unusual_source':
            if not event.username:
                continue
            previous = [item for item in history if item.event_type == 'login_success' and item.username == event.username and utc(item.timestamp) < utc(event.timestamp)]
            if len(previous) < threshold or any(item.source_ip == event.source_ip for item in previous):
                continue
            evidence = previous + [event]
        ports = {item.destination_port for item in evidence if item.destination_port is not None}
        accounts = {item.username for item in evidence if item.username}
        count = len(ports) if kind == 'distinct_ports' else len(accounts) if kind == 'accounts' else len(evidence)
        if count < threshold:
            continue
        # Rolling suppression avoids duplicate alerts at fixed clock-bucket boundaries.
        if kind != 'single':
            recent = db.scalar(select(Alert).where(Alert.detection_rule == stored.id, Alert.source_ip == event.source_ip, Alert.affected_host == event.hostname, Alert.timestamp >= since, Alert.timestamp <= event.timestamp).limit(1))
            if recent:
                continue
        key = sha256(f'{stored.id}:{event.event_id}'.encode()).hexdigest()
        if db.scalar(select(Alert.alert_id).where(Alert.dedup_key == key)):
            continue
        asset = db.scalar(select(Asset).where(Asset.hostname == event.hostname))
        prior = db.scalar(select(func.count(func.distinct(Incident.incident_id))).select_from(Incident).join(IncidentAlert).join(Alert).where(Alert.source_ip == event.source_ip)) if event.source_ip else 0
        level = event.severity if event.event_type in ('suricata_alert', 'wazuh_alert') else rule['level']
        score, severity, factors = score_risk(level, len(evidence), asset.sensitivity if asset else 1, len(accounts), len(ports), prior)
        ids = [item.event_id for item in evidence]
        if event.event_id not in ids:
            ids.append(event.event_id)
        description = f'{rule["description"]} Observed {len(evidence)} matching records in a {options["window_seconds"]}-second window.'
        alert = Alert(title=rule['title'], description=description, timestamp=event.timestamp, severity=severity, risk_score=score, source_ip=event.source_ip, destination_ip=event.destination_ip, affected_host=event.hostname, username=event.username, event_type=event.event_type, category=options['category'], detection_rule=stored.id, technique_id=options['technique_id'], evidence={'event_ids': ids, 'matching_count': len(evidence), 'distinct_ports': len(ports), 'affected_accounts': len(accounts), 'window_seconds': options['window_seconds'], 'trigger_message': event.message, 'origin': event.origin}, risk_factors=factors, dedup_key=key)
        db.add(alert)
        db.flush()
        generated.append(alert)
    return generated
