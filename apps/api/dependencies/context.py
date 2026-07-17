from collections.abc import AsyncIterator
from typing import cast

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.config import Settings, get_settings
from aegis_core.database.session import create_engine, create_session_factory
from aegis_core.models import Session, User
from aegis_core.security.tokens import hash_token, utcnow

settings = get_settings()
engine = create_engine(settings)
session_factory = create_session_factory(engine)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        yield session


def get_app_settings() -> Settings:
    return get_settings()


async def current_user(
    db: AsyncSession = Depends(get_db),
    authorization: str | None = Header(default=None),
    app_settings: Settings = Depends(get_app_settings),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication failed")
    token_hash = hash_token(
        authorization.removeprefix("Bearer ").strip(),
        app_settings.token_hash_key.get_secret_value(),
    )
    result = await db.execute(
        select(Session, User)
        .join(User, User.id == Session.owner_id)
        .where(
            Session.token_hash == token_hash,
            Session.revoked_at.is_(None),
            Session.expires_at > utcnow(),
        )
    )
    row = result.first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication failed")
    session, user = row
    session.last_seen_at = utcnow()
    await db.commit()
    return cast(User, user)


def request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "")
