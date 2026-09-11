from functools import lru_cache
from secrets import token_urlsafe
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='../.env', extra='ignore')
    database_url: str = 'sqlite:///./sentinelai.db'
    jwt_secret: str = ''
    environment: str = 'development'
    cors_origins: str = 'http://localhost:5173,http://localhost:8080'
    cookie_secure: bool = False
    demo_mode: bool = False
    registration_enabled: bool = True
    bootstrap_admin_email: str = ''
    bootstrap_admin_password: str = ''
    ingest_api_key: str = ''
    ai_provider: str = 'local'
    ai_api_url: str = ''
    ai_api_key: str = ''
    ai_model: str = ''

    @model_validator(mode='after')
    def secure_configuration(self):
        if self.environment == 'production':
            if len(self.jwt_secret) < 32 or not self.cookie_secure:
                raise ValueError('Production requires a strong JWT_SECRET and COOKIE_SECURE=true')
            if not self.database_url.startswith('postgresql'):
                raise ValueError('Production requires PostgreSQL')
            if self.demo_mode:
                raise ValueError('Demo mode must be disabled in production')
        if not self.jwt_secret:
            self.jwt_secret = token_urlsafe(48)
        if len(self.jwt_secret) < 32:
            raise ValueError('JWT_SECRET must contain at least 32 characters')
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
