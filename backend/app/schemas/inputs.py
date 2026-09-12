from datetime import datetime, timedelta, timezone
from typing import Literal
from ipaddress import ip_address
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.models.entities import uid

Severity = Literal["informational", "low", "medium", "high", "critical"]
Status = Literal["New", "Investigating", "Resolved", "False Positive"]
Role = Literal["admin", "analyst", "viewer"]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Credentials(Input):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value):
        return value.lower()


class Registration(Credentials):
    name: str = Field(min_length=2, max_length=100)

    @field_validator("password")
    @classmethod
    def strong_password(cls, value):
        if len(value) < 12 or not any(c.isalpha() for c in value) or not any(c.isdigit() for c in value):
            raise ValueError("Use at least 12 characters including letters and numbers")
        return value


class EventInput(Input):
    event_id: str = Field(default_factory=uid, min_length=1, max_length=100)
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    hostname: str = Field(min_length=1, max_length=253)
    username: str | None = Field(default=None, max_length=100)
    event_type: str = Field(min_length=1, max_length=80)
    protocol: str | None = Field(default=None, max_length=20)
    severity: Severity = "informational"
    message: str = Field(default="", max_length=8192)
    process_name: str | None = Field(default=None, max_length=512)
    file_path: str | None = Field(default=None, max_length=1024)
    device_id: str | None = Field(default=None, max_length=100)
    detection_rule: str | None = Field(default=None, max_length=100)
    status: str = Field(default="received", max_length=30)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value)) if value else None

    @field_validator("timestamp")
    @classmethod
    def valid_time(cls, value):
        if value.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        if value > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError("Timestamp is too far in the future")
        return value.astimezone(timezone.utc)


class EventBatch(Input):
    events: list[EventInput] = Field(min_length=1, max_length=500)


class AlertPatch(Input):
    status: Status | None = None
    assigned_to: str | None = None


class NoteInput(Input):
    text: str = Field(min_length=1, max_length=5000)


class IncidentCreate(Input):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    related_alerts: list[str] = Field(min_length=1, max_length=100)
    assigned_analyst: str | None = None


class IncidentPatch(Input):
    status: Status | None = None
    assigned_analyst: str | None = None
    resolution: str | None = Field(default=None, max_length=5000)
    note: str | None = Field(default=None, min_length=1, max_length=5000)


class UserPatch(Input):
    role: Role | None = None
    active: bool | None = None


class RulePatch(Input):
    enabled: bool


class AssetPatch(Input):
    operating_system: str = Field(min_length=1, max_length=100)
    sensitivity: int = Field(ge=1, le=3)
