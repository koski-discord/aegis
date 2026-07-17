import base64
import hashlib
import hmac
import json
import secrets
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import generate_authentication_options, generate_registration_options, options_to_json
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
)

from aegis_core.config import Settings
from aegis_core.exceptions import AuthenticationFailed, ConflictError, NotFoundError
from aegis_core.models import (
    DeviceApproval,
    MfaChallenge,
    MfaFactor,
    PendingTotpEnrollment,
    RecoveryCode,
    StepUpGrant,
    TotpFactor,
    TrustedDevice,
    User,
)
from aegis_core.security.mfa import (
    AssuranceLevel,
    ChallengeStatus,
    DeviceApprovalStatus,
    FactorStatus,
    FactorType,
    TotpEnrollmentStatus,
    VerificationPurpose,
)
from aegis_core.security.tokens import utcnow
from apps.api.services.mfa_crypto import encrypt_mfa_secret
from apps.api.services.mfa_policy import MfaPolicyEngine
from apps.api.services.recovery_codes import (
    generate_recovery_codes,
    hash_recovery_code,
    recovery_hint,
    verify_recovery_code,
)
from apps.api.services.security_events import record_security_event
from apps.api.services.totp import create_totp_enrollment_material, decrypt_totp_secret, verify_totp_code


def _hash_context(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode()).hexdigest()


async def start_totp_enrollment(
    db: AsyncSession,
    *,
    user: User,
    settings: Settings,
    display_name: str,
    replace_factor_id: UUID | None,
) -> PendingTotpEnrollment:
    await db.execute(
        update(PendingTotpEnrollment)
        .where(PendingTotpEnrollment.user_id == user.id, PendingTotpEnrollment.status == TotpEnrollmentStatus.pending)
        .values(status=TotpEnrollmentStatus.canceled, canceled_at=utcnow())
    )
    material = create_totp_enrollment_material(settings, user.id)
    factor = MfaFactor(
        user_id=user.id,
        factor_type=FactorType.totp,
        display_name=display_name,
        status=FactorStatus.pending,
    )
    db.add(factor)
    await db.flush()
    encrypted, nonce, key_id = encrypt_mfa_secret(
        plaintext=material.secret,
        settings=settings,
        user_id=user.id,
        factor_id=factor.id,
        factor_type=FactorType.totp,
    )
    enrollment = PendingTotpEnrollment(
        user_id=user.id,
        factor_id=factor.id,
        encrypted_secret=encrypted,
        nonce=nonce,
        encryption_key_version=key_id,
        expires_at=material.expires_at,
        status=TotpEnrollmentStatus.replacement_pending if replace_factor_id else TotpEnrollmentStatus.pending,
    )
    db.add(enrollment)
    await record_security_event(db, owner_id=user.id, event_type="totp_enrollment_started")
    await db.flush()
    return enrollment


async def get_totp_enrollment(db: AsyncSession, user: User, enrollment_id: UUID) -> PendingTotpEnrollment:
    result = await db.execute(
        select(PendingTotpEnrollment).where(
            PendingTotpEnrollment.id == enrollment_id,
            PendingTotpEnrollment.user_id == user.id,
            PendingTotpEnrollment.canceled_at.is_(None),
        )
    )
    enrollment = result.scalar_one_or_none()
    if enrollment is None:
        raise NotFoundError("enrollment not found")
    if enrollment.expires_at < utcnow():
        enrollment.status = TotpEnrollmentStatus.expired
        raise NotFoundError("enrollment not found")
    return enrollment


async def verify_totp_enrollment(
    db: AsyncSession,
    *,
    user: User,
    settings: Settings,
    enrollment_id: UUID,
    code: str,
) -> tuple[MfaFactor, list[str]]:
    enrollment = await get_totp_enrollment(db, user, enrollment_id)
    if enrollment.factor_id is None:
        raise ConflictError("enrollment has no factor")
    secret = decrypt_totp_secret(
        settings,
        encrypted_secret=enrollment.encrypted_secret,
        nonce=enrollment.nonce,
        key_id=enrollment.encryption_key_version,
        user_id=user.id,
        factor_id=enrollment.factor_id,
    )
    ok, counter = verify_totp_code(secret=secret, code=code, last_accepted_counter=None)
    if not ok or counter is None:
        await record_security_event(db, owner_id=user.id, event_type="totp_verification_failed")
        raise AuthenticationFailed("verification failed")
    result = await db.execute(
        select(MfaFactor).where(MfaFactor.id == enrollment.factor_id, MfaFactor.user_id == user.id)
    )
    factor = result.scalar_one()
    factor.status = FactorStatus.active
    factor.verified_at = utcnow()
    factor.last_used_at = utcnow()
    enrollment.status = TotpEnrollmentStatus.active
    enrollment.verified_at = utcnow()
    totp_factor = TotpFactor(
        factor_id=factor.id,
        encrypted_secret=enrollment.encrypted_secret,
        nonce=enrollment.nonce,
        encryption_key_version=enrollment.encryption_key_version,
        algorithm=enrollment.algorithm,
        digits=enrollment.digits,
        period=enrollment.period,
        last_accepted_counter=counter,
    )
    db.add(totp_factor)
    codes = generate_recovery_codes()
    await regenerate_recovery_codes(db, user=user, settings=settings, replacement_codes=codes)
    await record_security_event(db, owner_id=user.id, event_type="totp_enrollment_completed")
    return factor, codes


async def create_challenge(
    db: AsyncSession,
    *,
    user: User,
    purpose: VerificationPurpose,
    requested_resource: str | None = None,
    required_assurance: AssuranceLevel | None = None,
) -> MfaChallenge:
    decision = MfaPolicyEngine().evaluate(purpose)
    challenge = MfaChallenge(
        user_id=user.id,
        session_id=None,
        purpose=purpose,
        required_assurance=required_assurance or decision.minimum_assurance,
        expires_at=utcnow() + timedelta(seconds=decision.challenge_lifetime_seconds),
        request_context_hash=_hash_context(requested_resource),
        resource_id=requested_resource,
    )
    db.add(challenge)
    await db.flush()
    return challenge


async def _get_pending_challenge(db: AsyncSession, user: User, challenge_id: UUID) -> MfaChallenge:
    result = await db.execute(
        select(MfaChallenge).where(
            MfaChallenge.id == challenge_id,
            MfaChallenge.user_id == user.id,
            MfaChallenge.status == ChallengeStatus.pending,
        )
    )
    challenge = result.scalar_one_or_none()
    if challenge is None or challenge.expires_at < utcnow() or challenge.attempt_count >= challenge.max_attempts:
        raise AuthenticationFailed("verification failed")
    return challenge


async def verify_challenge_with_totp(
    db: AsyncSession,
    *,
    user: User,
    settings: Settings,
    challenge_id: UUID,
    code: str,
) -> StepUpGrant:
    challenge = await _get_pending_challenge(db, user, challenge_id)
    result = await db.execute(
        select(MfaFactor, TotpFactor)
        .join(TotpFactor, TotpFactor.factor_id == MfaFactor.id)
        .where(
            MfaFactor.user_id == user.id,
            MfaFactor.factor_type == FactorType.totp,
            MfaFactor.status == FactorStatus.active,
        )
        .with_for_update()
    )
    row = result.first()
    if row is None:
        raise AuthenticationFailed("verification failed")
    factor, totp_factor = row
    secret = decrypt_totp_secret(
        settings,
        encrypted_secret=totp_factor.encrypted_secret,
        nonce=totp_factor.nonce,
        key_id=totp_factor.encryption_key_version,
        user_id=user.id,
        factor_id=factor.id,
    )
    ok, counter = verify_totp_code(
        secret=secret,
        code=code,
        last_accepted_counter=totp_factor.last_accepted_counter,
        digits=totp_factor.digits,
        period=totp_factor.period,
    )
    challenge.attempt_count += 1
    if not ok or counter is None:
        await record_security_event(db, owner_id=user.id, event_type="totp_verification_failed")
        raise AuthenticationFailed("verification failed")
    totp_factor.last_accepted_counter = counter
    factor.last_used_at = utcnow()
    return await complete_challenge(db, user=user, challenge=challenge, assurance=AssuranceLevel.aal2)


async def complete_challenge(
    db: AsyncSession, *, user: User, challenge: MfaChallenge, assurance: AssuranceLevel
) -> StepUpGrant:
    now = utcnow()
    challenge.status = ChallengeStatus.completed
    challenge.completed_at = now
    challenge.consumed_at = now
    grant = StepUpGrant(
        user_id=user.id,
        session_id=challenge.session_id,
        assurance_level=assurance,
        approved_purposes=[challenge.purpose],
        expires_at=now + timedelta(minutes=5),
    )
    db.add(grant)
    await record_security_event(db, owner_id=user.id, event_type="step_up_verification_completed")
    await db.flush()
    return grant


async def regenerate_recovery_codes(
    db: AsyncSession,
    *,
    user: User,
    settings: Settings,
    replacement_codes: list[str] | None = None,
) -> list[str]:
    await db.execute(
        update(RecoveryCode)
        .where(RecoveryCode.user_id == user.id, RecoveryCode.consumed_at.is_(None), RecoveryCode.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    codes = replacement_codes or generate_recovery_codes()
    for code in codes:
        db.add(
            RecoveryCode(
                user_id=user.id,
                code_hash=hash_recovery_code(code, settings),
                code_hint=recovery_hint(code),
            )
        )
    await record_security_event(db, owner_id=user.id, event_type="recovery_codes_generated")
    await db.flush()
    return codes


async def recovery_code_status(db: AsyncSession, user: User) -> int:
    result = await db.execute(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.consumed_at.is_(None),
            RecoveryCode.revoked_at.is_(None),
        )
    )
    return len(list(result.scalars()))


async def verify_challenge_with_recovery_code(
    db: AsyncSession,
    *,
    user: User,
    settings: Settings,
    challenge_id: UUID,
    code: str,
) -> StepUpGrant:
    challenge = await _get_pending_challenge(db, user, challenge_id)
    result = await db.execute(
        select(RecoveryCode)
        .where(RecoveryCode.user_id == user.id, RecoveryCode.consumed_at.is_(None), RecoveryCode.revoked_at.is_(None))
        .with_for_update()
    )
    challenge.attempt_count += 1
    for recovery_code in result.scalars():
        if verify_recovery_code(code, recovery_code.code_hash, settings):
            recovery_code.consumed_at = utcnow()
            await record_security_event(db, owner_id=user.id, event_type="recovery_code_used")
            return await complete_challenge(db, user=user, challenge=challenge, assurance=AssuranceLevel.aal2)
    raise AuthenticationFailed("verification failed")


def create_webauthn_options(settings: Settings, user: User, purpose: str) -> tuple[str, dict[str, Any]]:
    challenge_bytes = secrets.token_bytes(32)
    challenge = bytes_to_base64url(challenge_bytes)
    options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions
    if purpose == "registration":
        options = generate_registration_options(
            rp_id=settings.webauthn_rp_id,
            rp_name=settings.webauthn_rp_name,
            user_name=str(user.discord_user_id),
            user_id=str(user.id).encode(),
            user_display_name=f"Aegis account {str(user.id)[:8]}",
            challenge=challenge_bytes,
            attestation=AttestationConveyancePreference.NONE,
        )
    else:
        options = generate_authentication_options(
            rp_id=settings.webauthn_rp_id,
            challenge=challenge_bytes,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
    return challenge, json.loads(options_to_json(options))


def validate_webauthn_challenge(expected_challenge: str, credential: dict[str, Any]) -> None:
    supplied = str(credential.get("challenge", ""))
    if not hmac.compare_digest(expected_challenge, supplied):
        raise AuthenticationFailed("verification failed")


async def list_factors(db: AsyncSession, user: User) -> list[MfaFactor]:
    result = await db.execute(
        select(MfaFactor).where(MfaFactor.user_id == user.id).order_by(MfaFactor.created_at.desc())
    )
    return list(result.scalars())


async def disable_factor(db: AsyncSession, user: User, factor_id: UUID) -> None:
    result = await db.execute(select(MfaFactor).where(MfaFactor.id == factor_id, MfaFactor.user_id == user.id))
    factor = result.scalar_one_or_none()
    if factor is None:
        raise NotFoundError("factor not found")
    factor.status = FactorStatus.disabled
    factor.disabled_at = utcnow()
    await record_security_event(db, owner_id=user.id, event_type="mfa_factor_disabled")


async def list_trusted_devices(db: AsyncSession, user: User) -> list[TrustedDevice]:
    result = await db.execute(
        select(TrustedDevice).where(TrustedDevice.user_id == user.id).order_by(TrustedDevice.created_at.desc())
    )
    return list(result.scalars())


async def rename_trusted_device(db: AsyncSession, user: User, device_id: UUID, name: str) -> TrustedDevice:
    result = await db.execute(
        select(TrustedDevice).where(TrustedDevice.id == device_id, TrustedDevice.user_id == user.id)
    )
    device = result.scalar_one_or_none()
    if device is None:
        raise NotFoundError("device not found")
    device.name = name
    return device


async def revoke_trusted_device(db: AsyncSession, user: User, device_id: UUID) -> None:
    result = await db.execute(
        select(TrustedDevice).where(TrustedDevice.id == device_id, TrustedDevice.user_id == user.id)
    )
    device = result.scalar_one_or_none()
    if device is None:
        raise NotFoundError("device not found")
    device.revoked_at = utcnow()
    await record_security_event(db, owner_id=user.id, event_type="trusted_device_revoked")


async def create_device_approval(
    db: AsyncSession, *, user: User, action_type: str, trusted_device_id: UUID | None
) -> DeviceApproval:
    approval = DeviceApproval(
        user_id=user.id,
        trusted_device_id=trusted_device_id,
        action_type=action_type,
        matching_code=f"{secrets.randbelow(1_000_000):06d}",
        expires_at=utcnow() + timedelta(minutes=5),
    )
    db.add(approval)
    await record_security_event(db, owner_id=user.id, event_type="device_approval_requested")
    await db.flush()
    return approval


async def decide_device_approval(
    db: AsyncSession,
    *,
    user: User,
    approval_id: UUID,
    approve: bool,
    signature: str | None,
) -> DeviceApproval:
    result = await db.execute(
        select(DeviceApproval).where(
            DeviceApproval.id == approval_id,
            DeviceApproval.user_id == user.id,
            DeviceApproval.status == DeviceApprovalStatus.pending,
        )
    )
    approval = result.scalar_one_or_none()
    if approval is None or approval.expires_at < utcnow():
        raise NotFoundError("approval not found")
    if approve:
        if not signature:
            raise AuthenticationFailed("verification failed")
        approval.status = DeviceApprovalStatus.approved
        approval.signature = signature
        approval.approved_at = utcnow()
        await record_security_event(db, owner_id=user.id, event_type="device_approval_accepted")
    else:
        approval.status = DeviceApprovalStatus.rejected
        approval.rejected_at = utcnow()
        await record_security_event(db, owner_id=user.id, event_type="device_approval_rejected")
    return approval


def webauthn_challenge_hash(challenge: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(challenge.encode()).digest()).decode().rstrip("=")
