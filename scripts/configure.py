#!/usr/bin/env python3
"""Generate private local credentials once, without printing secrets."""

from pathlib import Path
import secrets
import os

path = Path(__file__).resolve().parents[1] / ".env"
if path.exists():
    print(".env already exists; no changes made.")
else:

    def secret():
        return secrets.token_urlsafe(36)

    values = {
        "ENVIRONMENT": "development",
        "POSTGRES_DB": "sentinelai",
        "POSTGRES_USER": "sentinelai",
        "POSTGRES_PASSWORD": secret(),
        "JWT_SECRET": secret(),
        "BOOTSTRAP_ADMIN_EMAIL": "admin@sentinelai.local",
        "BOOTSTRAP_ADMIN_PASSWORD": "Sa1-" + secret(),
        "INGEST_API_KEY": secret(),
        "DEMO_MODE": "true",
        "REGISTRATION_ENABLED": "true",
        "COOKIE_SECURE": "false",
        "CORS_ORIGINS": "http://localhost:5173,http://localhost:8080",
        "AI_PROVIDER": "local",
        "AI_API_URL": "",
        "AI_API_KEY": "",
        "AI_MODEL": "",
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write("# Local generated secrets. Never commit this file.\n")
        file.write("\n".join(f"{key}={value}" for key, value in values.items()) + "\n")
    print(
        "Created private .env with unique database, JWT, collector, and administrator credentials."
    )
    print("Sign in as admin@sentinelai.local using BOOTSTRAP_ADMIN_PASSWORD from .env.")
