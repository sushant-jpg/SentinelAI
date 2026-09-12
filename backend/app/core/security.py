import hashlib
import secrets
from datetime import timedelta, timezone
import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pwdlib import PasswordHash
from sqlalchemy import select, func, delete, text
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.database.session import get_db
from app.models.entities import AuthSession, User, LoginAttempt, AuditLog, now

password_hasher = PasswordHash.recommended()
DUMMY_HASH = password_hasher.hash(secrets.token_urlsafe(24))
bearer = HTTPBearer(auto_error=False)


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def audit(db: Session, request: Request, user: str, action: str, target: str):
    db.add(AuditLog(user=user, action=action, target=target, source_ip=request.client.host if request.client else "unknown"))


def rate_limit(db: Session, key: str, limit: int = 5):
    cutoff = now() - timedelta(minutes=15)
    key = digest(key)
    if db.bind.dialect.name == "postgresql":
        lock_key = int(key[:15], 16)
        db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
    db.execute(delete(LoginAttempt).where(LoginAttempt.timestamp < cutoff))
    count = db.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.key == key, LoginAttempt.timestamp >= cutoff))
    if count >= limit:
        raise HTTPException(429, "Too many attempts. Try again in 15 minutes.", headers={"Retry-After": "900"})
    db.add(LoginAttempt(key=key))
    db.commit()


def issue_tokens(db: Session, user: User, session: AuthSession | None = None):
    refresh = secrets.token_urlsafe(48)
    if session is None:
        session = AuthSession(user_id=user.id, refresh_hash=digest(refresh), expires_at=now() + timedelta(days=7))
        db.add(session)
        db.flush()
    else:
        session.refresh_hash = digest(refresh)
    token = jwt.encode(
        {"sub": user.id, "sid": session.id, "iat": now(), "exp": now() + timedelta(minutes=15), "iss": "sentinelai", "aud": "sentinelai-ui", "type": "access"},
        get_settings().jwt_secret,
        algorithm="HS256",
    )
    return token, refresh


def current_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not credentials:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = jwt.decode(
            credentials.credentials,
            get_settings().jwt_secret,
            algorithms=["HS256"],
            audience="sentinelai-ui",
            issuer="sentinelai",
            options={"require": ["exp", "iat", "sub", "sid", "type"]},
        )
        if claims["type"] != "access":
            raise ValueError("Invalid token type")
        session = db.get(AuthSession, claims["sid"])
        user = db.get(User, claims["sub"])
        if not session or session.revoked or session.user_id != claims["sub"] or utc(session.expires_at) <= now() or not user or not user.active:
            raise ValueError("Invalid session")
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise HTTPException(401, "Invalid or expired session") from None
    request.state.session_id = session.id
    return user


def roles(*allowed):
    def dependency(user: User = Depends(current_user)):
        if user.role not in allowed:
            raise HTTPException(403, "Insufficient permissions")
        return user

    return dependency


analyst = roles("admin", "analyst")
admin = roles("admin")


def ingest_identity(request: Request, db: Session = Depends(get_db), credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    supplied = request.headers.get("X-Ingest-Key", "")
    configured = get_settings().ingest_api_key
    if supplied and configured and secrets.compare_digest(supplied, configured):
        return "collector"
    user = current_user(request, credentials, db)
    if user.role not in ("admin", "analyst"):
        raise HTTPException(403, "Insufficient permissions")
    return user.email
