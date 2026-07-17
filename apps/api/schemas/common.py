from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

FORBIDDEN_PLAINTEXT_FIELDS = {
    "password",
    "passphrase",
    "secret",
    "plaintext",
    "plain_text",
    "recovery_key",
    "master_password",
    "username",
    "login",
    "note",
    "url",
}


class StrictEncryptedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def reject_plaintext_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            forbidden = FORBIDDEN_PLAINTEXT_FIELDS.intersection({str(key).lower() for key in data})
            if forbidden:
                raise ValueError("request contains fields that must be encrypted locally")
        return data


class ErrorResponse(BaseModel):
    error: str
    request_id: str | None = None


class Page(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: str | None = None


class VersionInfo(BaseModel):
    name: str = "Aegis"
    api_version: str = "v1"
    schema_version: int = 1


class IdempotencyHeaders(BaseModel):
    idempotency_key: str | None = Field(default=None, max_length=128)
