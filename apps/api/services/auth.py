import hashlib
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.config import Settings
from aegis_core.models import Device, Session, User
from aegis_core.security.tokens import expires_at, hash_token, new_token


def safe_user_hash(discord_user_id: int, settings: Settings) -> str:
    return hashlib.sha256(f"{settings.token_hash_key.get_secret_value()}:{discord_user_id}".encode()).hexdigest()


async def get_or_create_user(db: AsyncSession, discord_user_id: int, settings: Settings) -> User:
    result = await db.execute(select(User).where(User.discord_user_id == discord_user_id))
    user = result.scalar_one_or_none()
    if user is not None:
        return user
    user = User(discord_user_id=discord_user_id, safe_user_hash=safe_user_hash(discord_user_id, settings))
    db.add(user)
    await db.flush()
    return user


async def create_session(
    db: AsyncSession,
    *,
    owner_id: UUID,
    device_name: str | None,
    settings: Settings,
) -> tuple[str, Session]:
    device_id = None
    if device_name:
        device = Device(owner_id=owner_id, name=device_name, public_label=device_name[:128])
        db.add(device)
        await db.flush()
        device_id = device.id
    token = new_token()
    session = Session(
        owner_id=owner_id,
        device_id=device_id,
        token_hash=hash_token(token, settings.token_hash_key.get_secret_value()),
        expires_at=expires_at(settings.session_ttl_seconds),
    )
    db.add(session)
    await db.flush()
    return token, session
