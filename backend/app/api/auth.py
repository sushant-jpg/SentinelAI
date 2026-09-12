from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.security import current_user, password_hasher, DUMMY_HASH, audit, rate_limit, issue_tokens, digest, utc
from app.database.session import get_db
from app.models.entities import User, AuthSession, now
from app.schemas.inputs import Credentials, Registration

router = APIRouter(prefix="/auth", tags=["Authentication"])


def public_user(user):
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role, "active": user.active}


def cookie(response, value):
    response.set_cookie("sentinel_refresh", value, httponly=True, secure=get_settings().cookie_secure, samesite="strict", path="/api/auth", max_age=604800)
    response.headers["Cache-Control"] = "no-store"


def check_origin(request):
    origin = request.headers.get("origin")
    if origin and origin not in get_settings().cors_origins.split(","):
        raise HTTPException(403, "Origin not allowed")


@router.post("/register", status_code=201)
def register(body: Registration, request: Request, db: Session = Depends(get_db)):
    if not get_settings().registration_enabled:
        raise HTTPException(403, "Registration is disabled")
    rate_limit(db, "register:" + request.client.host, 10)
    user = User(email=body.email, name=body.name, password_hash=password_hasher.hash(body.password), role="viewer")
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Account cannot be registered") from None
    audit(db, request, user.email, "user.register", user.id)
    db.commit()
    return public_user(user)


@router.post("/login")
def login(body: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    check_origin(request)
    rate_limit(db, "login:ip:" + request.client.host, 20)
    rate_limit(db, "login:account:" + body.email)
    user = db.scalar(select(User).where(User.email == body.email))
    valid = password_hasher.verify(body.password, user.password_hash if user else DUMMY_HASH)
    if not user or not valid or not user.active:
        audit(db, request, "anonymous", "auth.login_failed", "authentication")
        db.commit()
        raise HTTPException(401, "Invalid email or password")
    token, refresh = issue_tokens(db, user)
    audit(db, request, user.email, "auth.login", user.id)
    db.commit()
    cookie(response, refresh)
    return {"access_token": token, "token_type": "bearer", "user": public_user(user)}


@router.post("/refresh")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    check_origin(request)
    old_hash = digest(request.cookies.get("sentinel_refresh", ""))
    session = db.scalar(select(AuthSession).where(AuthSession.refresh_hash == old_hash))
    if not session or session.revoked or utc(session.expires_at) <= now():
        raise HTTPException(401, "Refresh session expired")
    user = db.get(User, session.user_id)
    if not user or not user.active:
        raise HTTPException(401, "Session unavailable")
    # Compare-and-swap prevents concurrent refreshes from both consuming one token.
    token, new_refresh = issue_tokens(db, user, session)
    new_hash = session.refresh_hash
    db.rollback()
    changed = db.execute(
        update(AuthSession)
        .where(AuthSession.id == session.id, AuthSession.refresh_hash == old_hash, AuthSession.revoked.is_(False))
        .values(refresh_hash=new_hash)
    )
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(401, "Refresh token already used")
    db.commit()
    cookie(response, new_refresh)
    return {"access_token": token, "token_type": "bearer", "user": public_user(user)}


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db), user: User = Depends(current_user)):
    check_origin(request)
    db.get(AuthSession, request.state.session_id).revoked = True
    audit(db, request, user.email, "auth.logout", user.id)
    db.commit()
    response.delete_cookie("sentinel_refresh", path="/api/auth")


@router.get("/me")
def me(user: User = Depends(current_user)):
    return public_user(user)
