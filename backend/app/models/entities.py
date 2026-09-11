from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import String, Text, DateTime, Integer, ForeignKey, JSON, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column
from app.database.session import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


def uid() -> str:
    return str(uuid4())


class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default='viewer')
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuthSession(Base):
    __tablename__ = 'auth_sessions'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'), index=True)
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class LoginAttempt(Base):
    __tablename__ = 'login_attempts'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    key: Mapped[str] = mapped_column(String(64), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)


class Event(Base):
    __tablename__ = 'events'
    event_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    username: Mapped[str | None] = mapped_column(String(100), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    protocol: Mapped[str | None] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    process_name: Mapped[str | None] = mapped_column(String(512))
    file_path: Mapped[str | None] = mapped_column(String(1024))
    device_id: Mapped[str | None] = mapped_column(String(100))
    detection_rule: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(30), default='received')
    origin: Mapped[str] = mapped_column(String(30), default='api')
    __table_args__ = (Index('ix_event_correlation', 'source_ip', 'hostname', 'timestamp'),)


class Asset(Base):
    __tablename__ = 'assets'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    hostname: Mapped[str] = mapped_column(String(253), unique=True)
    operating_system: Mapped[str] = mapped_column(String(100), default='Unknown')
    ip_address: Mapped[str | None] = mapped_column(String(45))
    agent_status: Mapped[str] = mapped_column(String(20), default='observed')
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    sensitivity: Mapped[int] = mapped_column(Integer, default=1)


class DetectionRule(Base):
    __tablename__ = 'detection_rules'
    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    definition: Mapped[dict] = mapped_column(JSON)


class MitreTechnique(Base):
    __tablename__ = 'mitre_techniques'
    technique_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    technique_name: Mapped[str] = mapped_column(String(100))
    tactic: Mapped[str] = mapped_column(String(100))


class Alert(Base):
    __tablename__ = 'alerts'
    alert_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    affected_host: Mapped[str] = mapped_column(String(253), index=True)
    username: Mapped[str | None] = mapped_column(String(100), index=True)
    event_type: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(100))
    detection_rule: Mapped[str] = mapped_column(ForeignKey('detection_rules.id'))
    technique_id: Mapped[str] = mapped_column(ForeignKey('mitre_techniques.technique_id'))
    status: Mapped[str] = mapped_column(String(30), default='New', index=True)
    assigned_to: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    evidence: Mapped[dict] = mapped_column(JSON)
    risk_factors: Mapped[list] = mapped_column(JSON)
    dedup_key: Mapped[str] = mapped_column(String(64), unique=True)


class AnalystNote(Base):
    __tablename__ = 'analyst_notes'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    alert_id: Mapped[str] = mapped_column(ForeignKey('alerts.alert_id'), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    text: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Incident(Base):
    __tablename__ = 'incidents'
    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30), default='New', index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    assigned_analyst: Mapped[str | None] = mapped_column(ForeignKey('users.id'))
    affected_assets: Mapped[list] = mapped_column(JSON)
    resolution: Mapped[str] = mapped_column(Text, default='')
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IncidentAlert(Base):
    __tablename__ = 'incident_alerts'
    incident_id: Mapped[str] = mapped_column(ForeignKey('incidents.incident_id'), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey('alerts.alert_id'), primary_key=True)


class IncidentTimeline(Base):
    __tablename__ = 'incident_timeline'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(ForeignKey('incidents.incident_id'), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String(100))
    note: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user: Mapped[str] = mapped_column(String(254))
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[str] = mapped_column(String(254))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    source_ip: Mapped[str] = mapped_column(String(45))
