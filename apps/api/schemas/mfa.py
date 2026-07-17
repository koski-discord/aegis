from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis_core.security.mfa import AssuranceLevel, VerificationPurpose

SECRET_FIELD_NAMES = {
    "totp_secret",
    "otp_secret",
    "setup_key",
    "qr",
    "qr_code",
    "recovery_code",
    "recovery_codes",
    "password",
    "master_password",
}


class MfaSafeModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def reject_secret_fields(cls, data: object) -> object:
        if isinstance(data, dict):
            forbidden = SECRET_FIELD_NAMES.intersection({str(key).lower() for key in data})
            if forbidden:
                raise ValueError("secret values must not be submitted through this endpoint")
        return data


class TotpEnrollmentStart(MfaSafeModel):
    display_name: str = Field(default="Authenticator app", min_length=1, max_length=128)
    replace_factor_id: UUID | None = None


class TotpEnrollmentOut(BaseModel):
    id: UUID
    expires_at: datetime
    manual_key_available: bool = True
    warning: str = (
        "Anyone who obtains this QR code or setup key may be able to generate valid verification codes. "
        "Do not save, share, photograph, or paste it into Discord."
    )


class TotpEnrollmentVerify(BaseModel):
    code: str = Field(pattern=r"^[0-9]{6}$")


class TotpEnrollmentVerifiedOut(BaseModel):
    factor_id: UUID
    recovery_codes: list[str]


class MfaChallengeCreate(MfaSafeModel):
    purpose: VerificationPurpose
    requested_resource: str | None = Field(default=None, max_length=128)
    required_assurance: AssuranceLevel | None = None


class MfaChallengeOut(BaseModel):
    id: UUID
    purpose: VerificationPurpose
    required_assurance: AssuranceLevel
    expires_at: datetime
    allowed_methods: list[str]


class TotpChallengeVerify(BaseModel):
    code: str = Field(pattern=r"^[0-9]{6}$")


class RecoveryChallengeVerify(BaseModel):
    code: str = Field(min_length=20, max_length=64)


class StepUpGrantOut(BaseModel):
    id: UUID
    assurance_level: AssuranceLevel
    expires_at: datetime


class RecoveryCodesOut(BaseModel):
    recovery_codes: list[str]
    warning: str = "Recovery codes are shown once. Store them offline and never paste them into Discord."


class RecoveryCodeStatusOut(BaseModel):
    unused_count: int


class FactorOut(BaseModel):
    id: UUID
    factor_type: str
    display_name: str
    status: str
    created_at: datetime
    verified_at: datetime | None
    last_used_at: datetime | None


class WebAuthnOptionsOut(BaseModel):
    challenge_id: UUID
    options: dict[str, object]


class WebAuthnRegistrationVerify(MfaSafeModel):
    challenge_id: UUID
    display_name: str = Field(min_length=1, max_length=128)
    credential: dict[str, object]


class WebAuthnAuthenticationVerify(MfaSafeModel):
    challenge_id: UUID
    credential: dict[str, object]


class TrustedDeviceOut(BaseModel):
    id: UUID
    name: str
    platform: str | None
    trust_expires_at: datetime
    revoked_at: datetime | None
    last_seen_at: datetime | None
    risk_state: str


class TrustedDeviceUpdate(MfaSafeModel):
    name: str = Field(min_length=1, max_length=128)


class DeviceApprovalCreate(MfaSafeModel):
    action_type: str = Field(min_length=1, max_length=64)
    trusted_device_id: UUID | None = None


class DeviceApprovalOut(BaseModel):
    id: UUID
    action_type: str
    matching_code: str
    status: str
    expires_at: datetime


class DeviceApprovalDecision(MfaSafeModel):
    signature: str = Field(min_length=16, max_length=4096)
