from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="AEGIS_", extra="ignore")

    environment: Literal["development", "testing", "production"] = "development"
    service_name: str = "aegis-api"
    public_base_url: AnyHttpUrl = "http://localhost:8000"  # type: ignore[assignment]
    database_url: str = "postgresql+asyncpg://aegis:aegis@postgres:5432/aegis"
    redis_url: str = "redis://redis:6379/0"

    discord_client_id: str = ""
    discord_client_secret: SecretStr = SecretStr("")
    discord_redirect_uri: str = "http://localhost:8000/api/v1/auth/discord/callback"
    discord_bot_token: SecretStr = SecretStr("")

    session_cookie_name: str = "aegis_session"
    session_ttl_seconds: int = 3600
    device_code_ttl_seconds: int = 600
    pending_action_ttl_seconds: int = 300
    oauth_state_ttl_seconds: int = 600
    max_request_body_bytes: int = 262_144
    allowed_origins: list[str] = Field(default_factory=lambda: ["http://localhost:8000"])
    trusted_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])

    token_hash_key: SecretStr = SecretStr("development-token-hash-key-change-me")
    state_signing_key: SecretStr = SecretStr("development-state-key-change-me")
    csrf_signing_key: SecretStr = SecretStr("development-csrf-key-change-me")
    bot_signing_public_keys: dict[str, str] = Field(default_factory=dict)
    bot_signing_private_key: SecretStr = SecretStr("")
    bot_signing_key_id: str = "dev-bot-key"

    production_https_only: bool = False
    docs_enabled: bool = True

    def require_production_safety(self) -> None:
        if self.environment != "production":
            return
        weak = {
            self.token_hash_key.get_secret_value(),
            self.state_signing_key.get_secret_value(),
            self.csrf_signing_key.get_secret_value(),
        }
        if any("development" in value or "change-me" in value for value in weak):
            raise RuntimeError("production secrets must be set explicitly")
        if not self.production_https_only:
            raise RuntimeError("production must enable HTTPS-only protections")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.require_production_safety()
    return settings
