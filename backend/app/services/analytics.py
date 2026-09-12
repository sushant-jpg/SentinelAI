from collections import Counter
from datetime import timedelta
from sqlalchemy import select, func
from app.models.entities import Alert, Incident, Asset, Event, now
from app.core.security import utc


def analytics(db, days: int):
    current = now()
    alerts = db.scalars(select(Alert).where(Alert.timestamp >= current - timedelta(days=days))).all()
    incidents = db.scalars(select(Incident)).all()
    severity = Counter(a.severity for a in alerts)
    resolved = [i for i in incidents if i.status == "Resolved" and i.resolved_at]
    trend = []
    for n in range(days - 1, -1, -1):
        date = (current - timedelta(days=n)).date()
        values = [a for a in alerts if utc(a.timestamp).date() == date]
        trend.append(
            {
                "date": date.isoformat(),
                "total": len(values),
                "critical": sum(a.severity == "critical" for a in values),
                "high": sum(a.severity == "high" for a in values),
            }
        )

    def top(field):
        return [{"name": name, "count": count} for name, count in Counter(getattr(a, field) for a in alerts if getattr(a, field)).most_common(6)]

    return {
        "total_alerts": len(alerts),
        "severity": {k: severity[k] for k in ("critical", "high", "medium", "low", "informational")},
        "alerts_today": sum(utc(a.timestamp).date() == current.date() for a in alerts),
        "active_incidents": sum(i.status in ("New", "Investigating") for i in incidents),
        "resolved_incidents": len(resolved),
        "monitored_devices": db.scalar(select(func.count()).select_from(Asset)),
        "total_events": db.scalar(select(func.count()).select_from(Event)),
        "trend": trend,
        "categories": top("category"),
        "top_ips": top("source_ip"),
        "top_hosts": top("affected_host"),
        "top_users": top("username"),
        "detections": top("title"),
        "mttr_hours": round(sum((utc(i.resolved_at) - utc(i.created_at)).total_seconds() / 3600 for i in resolved) / len(resolved), 2) if resolved else None,
        "days": days,
    }
