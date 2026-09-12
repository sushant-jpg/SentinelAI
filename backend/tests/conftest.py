import os
import tempfile

os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mktemp(prefix="sentinel-test-", suffix=".db")
os.environ["JWT_SECRET"] = "test-only-" + __import__("secrets").token_urlsafe(40)
os.environ["DEMO_MODE"] = "true"
os.environ["BOOTSTRAP_ADMIN_EMAIL"] = ""
os.environ["BOOTSTRAP_ADMIN_PASSWORD"] = ""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import Base, engine, SessionLocal
from app.models.entities import User
from app.core.security import password_hasher
from app.detection.rules import sync_rules


@pytest.fixture
def client():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        sync_rules(db)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def accounts(client):
    password = "Testing-Only-Password123!"
    with SessionLocal() as db:
        for role in ("admin", "analyst", "viewer"):
            db.add(User(email=f"{role}@example.test", name=role.title(), role=role, password_hash=password_hasher.hash(password)))
        db.commit()
    result = {}
    for role in ("admin", "analyst", "viewer"):
        response = client.post("/api/auth/login", json={"email": f"{role}@example.test", "password": password})
        assert response.status_code == 200
        result[role] = {"Authorization": "Bearer " + response.json()["access_token"]}
    return result
