import jwt
from app.database.session import SessionLocal
from app.models.entities import User, AuditLog
from sqlalchemy import select


def test_registration_and_no_privilege_escalation(client):
    details = {"email": "New@Example.test", "name": "New Viewer", "password": "long-test-password-123"}
    assert client.post("/api/auth/register", json={**details, "role": "admin"}).status_code == 422
    result = client.post("/api/auth/register", json=details)
    assert result.status_code == 201 and result.json()["role"] == "viewer"
    assert "password" not in str(result.json())
    assert client.post("/api/auth/register", json=details).status_code == 409
    with SessionLocal() as db:
        user = db.scalar(select(User))
        assert user.password_hash.startswith("$argon2id$") and details["password"] not in user.password_hash


def test_weak_password_errors_do_not_echo_secrets(client):
    secret = "weak-unique-secret"
    response = client.post("/api/auth/register", json={"email": "a@example.test", "name": "Test", "password": secret})
    assert response.status_code == 422 and secret not in response.text


def test_permissions_and_token_validation(client, accounts):
    for path in ("alerts", "events", "incidents", "assets", "analytics", "rules", "audit", "users", "settings"):
        assert client.get("/api/" + path).status_code == 401
    assert client.get("/api/users", headers=accounts["viewer"]).status_code == 403
    assert client.get("/api/audit", headers=accounts["analyst"]).status_code == 403
    assert client.post("/api/events/demo", headers=accounts["analyst"]).status_code == 403
    assert client.patch("/api/rules/port_scan", json={"enabled": False}, headers=accounts["viewer"]).status_code == 403
    forged = jwt.encode({"sub": "bad", "exp": 1}, "another-secret-with-enough-length-for-tests", algorithm="HS256")
    assert client.get("/api/alerts", headers={"Authorization": "Bearer " + forged}).status_code == 401


def test_rotation_logout_and_origin(client, accounts):
    login = client.post("/api/auth/login", json={"email": "analyst@example.test", "password": "Testing-Only-Password123!"})
    old_cookie = client.cookies.get("sentinel_refresh")
    assert "HttpOnly" in login.headers["set-cookie"] and "SameSite=strict" in login.headers["set-cookie"]
    refresh = client.post("/api/auth/refresh")
    assert refresh.status_code == 200
    assert client.cookies.get("sentinel_refresh") != old_cookie
    headers = {"Authorization": "Bearer " + refresh.json()["access_token"]}
    assert client.post("/api/auth/refresh", headers={"Origin": "https://untrusted.example"}).status_code == 403
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    assert client.post("/api/auth/refresh").status_code == 401
    with SessionLocal() as db:
        assert "auth.logout" in [a.action for a in db.scalars(select(AuditLog))]


def test_login_rate_limit(client):
    body = {"email": "missing@example.test", "password": "bad"}
    for _ in range(5):
        assert client.post("/api/auth/login", json=body).status_code == 401
    assert client.post("/api/auth/login", json=body).status_code == 429


def test_security_headers_and_body_limit(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert client.post("/api/auth/login", content="x" * 2_000_001).status_code == 413


def test_role_change_revokes_sessions(client, accounts):
    users = client.get("/api/users", headers=accounts["admin"]).json()["items"]
    viewer = next(u for u in users if u["role"] == "viewer")
    assert client.patch("/api/users/" + viewer["id"], headers=accounts["admin"], json={"role": "analyst"}).status_code == 200
    assert client.get("/api/alerts", headers=accounts["viewer"]).status_code == 401
    admin = next(u for u in users if u["role"] == "admin")
    assert client.patch("/api/users/" + admin["id"], headers=accounts["admin"], json={"active": False}).status_code == 422
