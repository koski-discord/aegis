from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class UserOut(BaseModel):
    id: UUID
    discord_user_id: int
    created_at: datetime


class DeviceAuthorizationStart(BaseModel):
    device_name: str = Field(min_length=1, max_length=128)


class DeviceAuthorizationOut(BaseModel):
    device_code: str
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int = 5


class DeviceTokenPoll(BaseModel):
    device_code: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: UUID | None
    expires_at: datetime
    revoked_at: datetime | None
    last_seen_at: datetime | None
