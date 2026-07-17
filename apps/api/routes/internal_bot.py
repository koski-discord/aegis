import base64
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.config import Settings
from aegis_core.exceptions import AuthenticationFailed, ConflictError, NotFoundError
from aegis_core.models import SecurityEvent, Session, User
from aegis_core.security.mfa import VerificationPurpose
from aegis_core.security.tokens import utcnow
from apps.api.dependencies.context import get_app_settings, get_db
from apps.api.services import mfa as mfa_service
from apps.api.services.auth import get_or_create_user
from apps.api.services.totp import decrypt_totp_secret, provisioning_uri, qr_png

router = APIRouter(prefix="/internal/bot", tags=["internal-bot"])


class BotUserPayload(BaseModel):
    discord_user_id: int


class BotTotpStartPayload(BotUserPayload):
    display_name: str = Field(default="Discord authenticator", min_length=1, max_length=128)


class BotTotpVerifyPayload(BotUserPayload):
    enrollment_id: UUID
    code: str = Field(pattern=r"^[0-9]{6}$")


class BotChallengePayload(BotUserPayload):
    purpose: VerificationPurpose = VerificationPurpose.login
    requested_resource: str | None = Field(default=None, max_length=128)


class BotChallengeVerifyPayload(BotUserPayload):
    challenge_id: UUID
    code: str = Field(pattern=r"^[0-9]{6}$")


async def _bot_user(db: AsyncSession, discord_user_id: int, settings: Settings) -> User:
    user = await get_or_create_user(db, discord_user_id, settings)
    await db.flush()
    return user


def _factor_out(factor: Any) -> dict[str, Any]:
    return {
        "id": str(factor.id),
        "type": factor.factor_type,
        "name": factor.display_name,
        "status": factor.status,
        "verified_at": factor.verified_at.isoformat() if factor.verified_at else None,
        "last_used_at": factor.last_used_at.isoformat() if factor.last_used_at else None,
    }


@router.post("/overview")
async def overview(
    payload: BotUserPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    factors = await mfa_service.list_factors(db, user)
    devices = await mfa_service.list_trusted_devices(db, user)
    recovery_count = await mfa_service.recovery_code_status(db, user)
    sessions_result = await db.execute(
        select(Session)
        .where(Session.owner_id == user.id, Session.revoked_at.is_(None), Session.expires_at > utcnow())
        .order_by(Session.created_at.desc())
    )
    events_result = await db.execute(
        select(SecurityEvent)
        .where(SecurityEvent.owner_id == user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(5)
    )
    await db.commit()
    return {
        "discord_user_id": payload.discord_user_id,
        "factors": [_factor_out(factor) for factor in factors],
        "trusted_devices": len(devices),
        "recovery_codes_remaining": recovery_count,
        "active_sessions": len(list(sessions_result.scalars().all())),
        "recent_events": [
            {
                "type": event.event_type,
                "created_at": event.created_at.isoformat(),
                "metadata": event.metadata_,
            }
            for event in events_result.scalars().all()
        ],
    }


@router.post("/totp/start")
async def start_totp(
    payload: BotTotpStartPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    enrollment = await mfa_service.start_totp_enrollment(
        db,
        user=user,
        settings=settings,
        display_name=payload.display_name,
        replace_factor_id=None,
    )
    if enrollment.factor_id is None:
        raise HTTPException(status_code=500, detail="enrollment was not linked to a factor")
    secret = decrypt_totp_secret(
        settings,
        encrypted_secret=enrollment.encrypted_secret,
        nonce=enrollment.nonce,
        key_id=enrollment.encryption_key_version,
        user_id=user.id,
        factor_id=enrollment.factor_id,
    )
    png = qr_png(provisioning_uri(secret, user.id))
    await db.commit()
    return {
        "enrollment_id": str(enrollment.id),
        "expires_at": enrollment.expires_at.isoformat(),
        "qr_png_base64": base64.b64encode(png).decode("ascii"),
        "warning": "Scan this QR code privately. Anyone who can scan it may generate your Aegis MFA codes.",
    }


@router.post("/totp/verify")
async def verify_totp(
    payload: BotTotpVerifyPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    try:
        factor, codes = await mfa_service.verify_totp_enrollment(
            db,
            user=user,
            settings=settings,
            enrollment_id=payload.enrollment_id,
            code=payload.code,
        )
    except (AuthenticationFailed, ConflictError, NotFoundError) as exc:
        await db.commit()
        raise HTTPException(status_code=400, detail="verification failed") from exc
    await db.commit()
    return {
        "factor_id": str(factor.id),
        "recovery_codes": codes,
        "warning": "Recovery codes are shown once. Store them offline and delete this Discord message when done.",
    }


@router.post("/challenge/start")
async def start_challenge(
    payload: BotChallengePayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    challenge = await mfa_service.create_challenge(
        db,
        user=user,
        purpose=payload.purpose,
        requested_resource=payload.requested_resource,
    )
    await db.commit()
    return {
        "challenge_id": str(challenge.id),
        "purpose": challenge.purpose,
        "required_assurance": challenge.required_assurance,
        "expires_at": challenge.expires_at.isoformat(),
    }


@router.post("/challenge/verify-totp")
async def verify_challenge_totp(
    payload: BotChallengeVerifyPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    try:
        grant = await mfa_service.verify_challenge_with_totp(
            db,
            user=user,
            settings=settings,
            challenge_id=payload.challenge_id,
            code=payload.code,
        )
    except AuthenticationFailed as exc:
        await db.commit()
        raise HTTPException(status_code=400, detail="verification failed") from exc
    await db.commit()
    return {
        "grant_id": str(grant.id),
        "assurance_level": grant.assurance_level,
        "expires_at": grant.expires_at.isoformat(),
    }


@router.post("/factors")
async def factors(
    payload: BotUserPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    factors_ = await mfa_service.list_factors(db, user)
    await db.commit()
    return {"factors": [_factor_out(factor) for factor in factors_]}


@router.post("/recovery-codes/status")
async def recovery_codes_status(
    payload: BotUserPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    count = await mfa_service.recovery_code_status(db, user)
    await db.commit()
    return {"unused_count": count}


@router.post("/recovery-codes/generate")
async def generate_recovery_codes(
    payload: BotUserPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    codes = await mfa_service.regenerate_recovery_codes(db, user=user, settings=settings)
    await db.commit()
    return {
        "recovery_codes": codes,
        "warning": "Recovery codes are shown once. Store them offline and never paste them into Discord channels.",
    }


@router.post("/devices")
async def devices(
    payload: BotUserPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    devices_ = await mfa_service.list_trusted_devices(db, user)
    await db.commit()
    return {
        "devices": [
            {
                "id": str(device.id),
                "name": device.name,
                "platform": device.platform,
                "risk_state": device.risk_state,
                "trust_expires_at": device.trust_expires_at.isoformat(),
                "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
                "revoked": device.revoked_at is not None,
            }
            for device in devices_
        ]
    }


@router.post("/sessions")
async def sessions(
    payload: BotUserPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    result = await db.execute(
        select(Session)
        .where(Session.owner_id == user.id)
        .order_by(Session.created_at.desc())
        .limit(10)
    )
    await db.commit()
    return {
        "sessions": [
            {
                "id": str(session.id),
                "active": session.revoked_at is None and session.expires_at > utcnow(),
                "expires_at": session.expires_at.isoformat(),
                "last_seen_at": session.last_seen_at.isoformat() if session.last_seen_at else None,
                "revoked_at": session.revoked_at.isoformat() if session.revoked_at else None,
            }
            for session in result.scalars().all()
        ]
    }


@router.post("/events")
async def events(
    payload: BotUserPayload,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> dict[str, Any]:
    user = await _bot_user(db, payload.discord_user_id, settings)
    result = await db.execute(
        select(SecurityEvent)
        .where(SecurityEvent.owner_id == user.id)
        .order_by(SecurityEvent.created_at.desc())
        .limit(10)
    )
    await db.commit()
    return {
        "events": [
            {
                "type": event.event_type,
                "created_at": event.created_at.isoformat(),
                "metadata": event.metadata_,
            }
            for event in result.scalars().all()
        ]
    }
