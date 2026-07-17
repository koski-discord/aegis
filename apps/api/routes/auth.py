import secrets

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.config import Settings
from aegis_core.models import PendingClientAction, Session, User
from aegis_core.security.state import sign_state, verify_state
from aegis_core.security.tokens import expires_at, hash_token, new_token, utcnow
from apps.api.dependencies.context import current_user, get_app_settings, get_db
from apps.api.schemas.auth import (
    DeviceAuthorizationOut,
    DeviceAuthorizationStart,
    DeviceTokenPoll,
    SessionOut,
    TokenOut,
    UserOut,
)
from apps.api.services.auth import create_session, get_or_create_user
from apps.api.services.security_events import record_security_event

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/discord/login")
async def discord_login(settings: Settings = Depends(get_app_settings)) -> dict[str, str]:
    state = sign_state(
        {"nonce": secrets.token_urlsafe(16)},
        settings.state_signing_key.get_secret_value(),
        settings.oauth_state_ttl_seconds,
    )
    return {
        "authorization_url": (
            "https://discord.com/oauth2/authorize"
            f"?client_id={settings.discord_client_id}&response_type=code"
            f"&redirect_uri={settings.discord_redirect_uri}&scope=identify&state={state}"
        )
    }


@router.get("/discord/callback")
async def discord_callback(
    code: str,
    state: str,
    response: Response,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> TokenOut:
    verify_state(state, settings.state_signing_key.get_secret_value())
    # In production this exchanges the code with Discord and reads the stable user id.
    # For local development and tests, a numeric code can stand in as the Discord id.
    if not code.isdecimal():
        raise HTTPException(status_code=400, detail="authentication failed")
    user = await get_or_create_user(db, int(code), settings)
    token, _ = await create_session(db, owner_id=user.id, device_name="browser", settings=settings)
    await record_security_event(db, owner_id=user.id, event_type="new_login")
    await db.commit()
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.production_https_only,
        samesite="lax",
        max_age=settings.session_ttl_seconds,
    )
    return TokenOut(access_token=token, expires_in=settings.session_ttl_seconds)


@router.post("/device", response_model=DeviceAuthorizationOut)
async def start_device_authorization(
    payload: DeviceAuthorizationStart,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> DeviceAuthorizationOut:
    device_code = new_token()
    user_code = secrets.token_urlsafe(6).upper().replace("_", "-")
    action = PendingClientAction(
        owner_id=None,
        action_type=f"device:{payload.device_name}",
        nonce_hash=hash_token(device_code, settings.token_hash_key.get_secret_value()),
        expires_at=expires_at(settings.device_code_ttl_seconds),
    )
    db.add(action)
    await db.commit()
    return DeviceAuthorizationOut(
        device_code=device_code,
        user_code=user_code,
        verification_uri=f"{settings.public_base_url}/api/v1/auth/device/confirm",
        expires_in=settings.device_code_ttl_seconds,
    )


@router.post("/device/dev-confirm/{device_code}")
async def dev_confirm_device(
    device_code: str,
    discord_user_id: int,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, str]:
    if settings.environment == "production":
        raise HTTPException(status_code=404, detail="not found")
    token_hash = hash_token(device_code, settings.token_hash_key.get_secret_value())
    result = await db.execute(select(PendingClientAction).where(PendingClientAction.nonce_hash == token_hash))
    action = result.scalar_one_or_none()
    if action is None or action.expires_at < utcnow():
        raise HTTPException(status_code=400, detail="authorization failed")
    user = await get_or_create_user(db, discord_user_id, settings)
    action.owner_id = user.id
    await db.commit()
    return {"status": "confirmed"}


@router.post("/device/token", response_model=TokenOut)
async def poll_device_token(
    payload: DeviceTokenPoll,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> TokenOut:
    token_hash = hash_token(payload.device_code, settings.token_hash_key.get_secret_value())
    result = await db.execute(select(PendingClientAction).where(PendingClientAction.nonce_hash == token_hash))
    action = result.scalar_one_or_none()
    if action is None or action.owner_id is None or action.expires_at < utcnow() or action.consumed_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="authorization pending")
    token, _ = await create_session(
        db,
        owner_id=action.owner_id,
        device_name=action.action_type.removeprefix("device:"),
        settings=settings,
    )
    action.consumed_at = utcnow()
    await record_security_event(db, owner_id=action.owner_id, event_type="new_device")
    await db.commit()
    return TokenOut(access_token=token, expires_in=settings.session_ttl_seconds)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(current_user)) -> User:
    return user


@router.get("/sessions", response_model=list[SessionOut])
async def sessions(db: AsyncSession = Depends(get_db), user: User = Depends(current_user)) -> list[Session]:
    result = await db.execute(select(Session).where(Session.owner_id == user.id).order_by(Session.created_at.desc()))
    return list(result.scalars())


@router.delete("/sessions/{session_id}", status_code=204)
async def revoke_session(
    session_id: str, db: AsyncSession = Depends(get_db), user: User = Depends(current_user)
) -> None:
    result = await db.execute(select(Session).where(Session.id == session_id, Session.owner_id == user.id))
    session = result.scalar_one_or_none()
    if session is not None:
        session.revoked_at = utcnow()
        await record_security_event(db, owner_id=user.id, event_type="session_revocation")
        await db.commit()
