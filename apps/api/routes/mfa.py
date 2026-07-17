from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.ext.asyncio import AsyncSession

from aegis_core.config import Settings
from aegis_core.exceptions import AuthenticationFailed, ConflictError, NotFoundError
from aegis_core.models import MfaFactor, User
from aegis_core.security.mfa import AssuranceLevel, FactorType, VerificationPurpose
from aegis_core.security.tokens import utcnow
from apps.api.dependencies.context import current_user, get_app_settings, get_db
from apps.api.schemas.mfa import (
    DeviceApprovalCreate,
    DeviceApprovalDecision,
    DeviceApprovalOut,
    FactorOut,
    MfaChallengeCreate,
    MfaChallengeOut,
    RecoveryChallengeVerify,
    RecoveryCodesOut,
    RecoveryCodeStatusOut,
    StepUpGrantOut,
    TotpChallengeVerify,
    TotpEnrollmentOut,
    TotpEnrollmentStart,
    TotpEnrollmentVerifiedOut,
    TrustedDeviceOut,
    TrustedDeviceUpdate,
    WebAuthnAuthenticationVerify,
    WebAuthnOptionsOut,
    WebAuthnRegistrationVerify,
)
from apps.api.services import mfa as service
from apps.api.services.mfa_policy import MfaPolicyEngine
from apps.api.services.totp import decrypt_totp_secret, provisioning_uri, qr_png

router = APIRouter(tags=["aegis-verify"])


def _generic_mfa_error(exc: Exception) -> HTTPException:
    if isinstance(exc, NotFoundError):
        return HTTPException(status_code=404, detail="not found")
    if isinstance(exc, ConflictError):
        return HTTPException(status_code=409, detail="conflict")
    return HTTPException(status_code=400, detail="verification failed")


@router.post("/mfa/totp/enrollments", response_model=TotpEnrollmentOut, status_code=201)
async def start_totp_enrollment(
    payload: TotpEnrollmentStart,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_app_settings),
) -> TotpEnrollmentOut:
    enrollment = await service.start_totp_enrollment(
        db,
        user=user,
        settings=settings,
        display_name=payload.display_name,
        replace_factor_id=payload.replace_factor_id,
    )
    await db.commit()
    return TotpEnrollmentOut(id=enrollment.id, expires_at=enrollment.expires_at)


@router.get("/mfa/totp/enrollments/{enrollment_id}/qr")
async def get_totp_qr(
    enrollment_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_app_settings),
) -> Response:
    try:
        enrollment = await service.get_totp_enrollment(db, user, enrollment_id)
        if enrollment.factor_id is None:
            raise NotFoundError("enrollment not found")
        secret = decrypt_totp_secret(
            settings,
            encrypted_secret=enrollment.encrypted_secret,
            nonce=enrollment.nonce,
            key_id=enrollment.encryption_key_version,
            user_id=user.id,
            factor_id=enrollment.factor_id,
        )
        image = qr_png(provisioning_uri(secret, user.id))
        return Response(
            content=image,
            media_type="image/png",
            headers={
                "Cache-Control": "no-store, private",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; img-src 'self' data:; frame-ancestors 'none'",
            },
        )
    except (AuthenticationFailed, ConflictError, NotFoundError) as exc:
        raise _generic_mfa_error(exc) from exc


@router.post("/mfa/totp/enrollments/{enrollment_id}/verify", response_model=TotpEnrollmentVerifiedOut)
async def verify_totp_enrollment(
    enrollment_id: UUID,
    payload: TotpChallengeVerify,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_app_settings),
) -> TotpEnrollmentVerifiedOut:
    try:
        factor, codes = await service.verify_totp_enrollment(
            db, user=user, settings=settings, enrollment_id=enrollment_id, code=payload.code
        )
        await db.commit()
        return TotpEnrollmentVerifiedOut(factor_id=factor.id, recovery_codes=codes)
    except (AuthenticationFailed, ConflictError, NotFoundError) as exc:
        raise _generic_mfa_error(exc) from exc


@router.delete("/mfa/totp/enrollments/{enrollment_id}", status_code=204)
async def cancel_totp_enrollment(
    enrollment_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> None:
    try:
        enrollment = await service.get_totp_enrollment(db, user, enrollment_id)
        enrollment.status = "canceled"
        enrollment.canceled_at = utcnow()
        await db.commit()
    except NotFoundError as exc:
        raise _generic_mfa_error(exc) from exc


@router.post("/mfa/challenges", response_model=MfaChallengeOut, status_code=201)
async def create_mfa_challenge(
    payload: MfaChallengeCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> MfaChallengeOut:
    challenge = await service.create_challenge(
        db,
        user=user,
        purpose=payload.purpose,
        requested_resource=payload.requested_resource,
        required_assurance=payload.required_assurance,
    )
    decision = MfaPolicyEngine().evaluate(payload.purpose)
    await db.commit()
    return MfaChallengeOut(
        id=challenge.id,
        purpose=payload.purpose,
        required_assurance=challenge.required_assurance,
        expires_at=challenge.expires_at,
        allowed_methods=[factor.value for factor in decision.allowed_factor_types],
    )


@router.post("/mfa/challenges/{challenge_id}/totp", response_model=StepUpGrantOut)
async def verify_mfa_challenge_totp(
    challenge_id: UUID,
    payload: TotpChallengeVerify,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_app_settings),
) -> StepUpGrantOut:
    try:
        grant = await service.verify_challenge_with_totp(
            db, user=user, settings=settings, challenge_id=challenge_id, code=payload.code
        )
        await db.commit()
        return StepUpGrantOut(id=grant.id, assurance_level=grant.assurance_level, expires_at=grant.expires_at)
    except AuthenticationFailed as exc:
        await db.commit()
        raise _generic_mfa_error(exc) from exc


@router.post("/mfa/challenges/{challenge_id}/recovery-code", response_model=StepUpGrantOut)
async def verify_mfa_challenge_recovery_code(
    challenge_id: UUID,
    payload: RecoveryChallengeVerify,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_app_settings),
) -> StepUpGrantOut:
    try:
        grant = await service.verify_challenge_with_recovery_code(
            db, user=user, settings=settings, challenge_id=challenge_id, code=payload.code
        )
        await db.commit()
        return StepUpGrantOut(id=grant.id, assurance_level=grant.assurance_level, expires_at=grant.expires_at)
    except AuthenticationFailed as exc:
        await db.commit()
        raise _generic_mfa_error(exc) from exc


@router.post("/mfa/recovery-codes/generate", response_model=RecoveryCodesOut)
async def generate_recovery_codes_route(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_app_settings),
) -> RecoveryCodesOut:
    codes = await service.regenerate_recovery_codes(db, user=user, settings=settings)
    await db.commit()
    return RecoveryCodesOut(recovery_codes=codes)


@router.get("/mfa/recovery-codes/status", response_model=RecoveryCodeStatusOut)
async def recovery_codes_status(
    db: AsyncSession = Depends(get_db), user: User = Depends(current_user)
) -> RecoveryCodeStatusOut:
    return RecoveryCodeStatusOut(unused_count=await service.recovery_code_status(db, user))


@router.post("/webauthn/registration/options", response_model=WebAuthnOptionsOut)
async def webauthn_registration_options(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_app_settings),
) -> WebAuthnOptionsOut:
    challenge_value, options = service.create_webauthn_options(settings, user, "registration")
    challenge = await service.create_challenge(db, user=user, purpose=VerificationPurpose.add_mfa_factor)
    challenge.request_context_hash = service.webauthn_challenge_hash(challenge_value)
    await db.commit()
    return WebAuthnOptionsOut(challenge_id=challenge.id, options=options)


@router.post("/webauthn/registration/verify", response_model=StepUpGrantOut)
async def webauthn_registration_verify(
    payload: WebAuthnRegistrationVerify,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> StepUpGrantOut:
    challenge = await service._get_pending_challenge(db, user, payload.challenge_id)
    supplied = str(payload.credential.get("challenge", ""))
    if challenge.request_context_hash != service.webauthn_challenge_hash(supplied):
        raise HTTPException(status_code=400, detail="verification failed")
    factor = MfaFactor(
        user_id=user.id,
        factor_type=FactorType.webauthn,
        display_name=payload.display_name,
        status="active",
        verified_at=utcnow(),
    )
    db.add(factor)
    grant = await service.complete_challenge(db, user=user, challenge=challenge, assurance=AssuranceLevel.aal3)
    await db.commit()
    return StepUpGrantOut(id=grant.id, assurance_level=grant.assurance_level, expires_at=grant.expires_at)


@router.post("/webauthn/authentication/options", response_model=WebAuthnOptionsOut)
async def webauthn_authentication_options(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
    settings: Settings = Depends(get_app_settings),
) -> WebAuthnOptionsOut:
    challenge_value, options = service.create_webauthn_options(settings, user, "authentication")
    challenge = await service.create_challenge(db, user=user, purpose=VerificationPurpose.login)
    challenge.request_context_hash = service.webauthn_challenge_hash(challenge_value)
    await db.commit()
    return WebAuthnOptionsOut(challenge_id=challenge.id, options=options)


@router.post("/webauthn/authentication/verify", response_model=StepUpGrantOut)
async def webauthn_authentication_verify(
    payload: WebAuthnAuthenticationVerify,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> StepUpGrantOut:
    challenge = await service._get_pending_challenge(db, user, payload.challenge_id)
    supplied = str(payload.credential.get("challenge", ""))
    if challenge.request_context_hash != service.webauthn_challenge_hash(supplied):
        raise HTTPException(status_code=400, detail="verification failed")
    grant = await service.complete_challenge(db, user=user, challenge=challenge, assurance=AssuranceLevel.aal3)
    await db.commit()
    return StepUpGrantOut(id=grant.id, assurance_level=grant.assurance_level, expires_at=grant.expires_at)


@router.get("/mfa/factors", response_model=list[FactorOut])
async def factors(db: AsyncSession = Depends(get_db), user: User = Depends(current_user)) -> list[FactorOut]:
    return [FactorOut.model_validate(factor, from_attributes=True) for factor in await service.list_factors(db, user)]


@router.delete("/mfa/factors/{factor_id}", status_code=204)
async def remove_factor(
    factor_id: UUID, db: AsyncSession = Depends(get_db), user: User = Depends(current_user)
) -> None:
    try:
        await service.disable_factor(db, user, factor_id)
        await db.commit()
    except NotFoundError as exc:
        raise _generic_mfa_error(exc) from exc


@router.get("/devices", response_model=list[TrustedDeviceOut])
async def devices(db: AsyncSession = Depends(get_db), user: User = Depends(current_user)) -> list[TrustedDeviceOut]:
    return [
        TrustedDeviceOut.model_validate(device, from_attributes=True)
        for device in await service.list_trusted_devices(db, user)
    ]


@router.patch("/devices/{device_id}", response_model=TrustedDeviceOut)
async def rename_device(
    device_id: UUID,
    payload: TrustedDeviceUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> TrustedDeviceOut:
    try:
        device = await service.rename_trusted_device(db, user, device_id, payload.name)
        await db.commit()
        return TrustedDeviceOut.model_validate(device, from_attributes=True)
    except NotFoundError as exc:
        raise _generic_mfa_error(exc) from exc


@router.delete("/devices/{device_id}", status_code=204)
async def revoke_device(
    device_id: UUID, db: AsyncSession = Depends(get_db), user: User = Depends(current_user)
) -> None:
    try:
        await service.revoke_trusted_device(db, user, device_id)
        await db.commit()
    except NotFoundError as exc:
        raise _generic_mfa_error(exc) from exc


@router.post("/device-approvals", response_model=DeviceApprovalOut, status_code=201)
async def create_device_approval(
    payload: DeviceApprovalCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> DeviceApprovalOut:
    approval = await service.create_device_approval(
        db, user=user, action_type=payload.action_type, trusted_device_id=payload.trusted_device_id
    )
    await db.commit()
    return DeviceApprovalOut.model_validate(approval, from_attributes=True)


@router.post("/device-approvals/{approval_id}/approve", response_model=DeviceApprovalOut)
async def approve_device_approval(
    approval_id: UUID,
    payload: DeviceApprovalDecision,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> DeviceApprovalOut:
    approval = await service.decide_device_approval(
        db, user=user, approval_id=approval_id, approve=True, signature=payload.signature
    )
    await db.commit()
    return DeviceApprovalOut.model_validate(approval, from_attributes=True)


@router.post("/device-approvals/{approval_id}/reject", response_model=DeviceApprovalOut)
async def reject_device_approval(
    approval_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_user),
) -> DeviceApprovalOut:
    approval = await service.decide_device_approval(
        db, user=user, approval_id=approval_id, approve=False, signature=None
    )
    await db.commit()
    return DeviceApprovalOut.model_validate(approval, from_attributes=True)
