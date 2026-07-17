import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from aegis_core.database.base import Base


def uuid4() -> uuid.UUID:
    return uuid.uuid4()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    discord_user_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False, index=True)
    safe_user_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    vault: Mapped["Vault"] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Vault(Base, TimestampMixin):
    __tablename__ = "vaults"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    kdf_salt: Mapped[str] = mapped_column(String(128), nullable=False)
    kdf_params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    kdf_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    encrypted_vault_metadata: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    owner: Mapped[User] = relationship(back_populates="vault")
    records: Mapped[list["EncryptedRecord"]] = relationship(back_populates="vault", cascade="all, delete-orphan")


class EncryptedRecord(Base, TimestampMixin):
    __tablename__ = "encrypted_records"
    __table_args__ = (
        Index("ix_records_owner_vault", "owner_id", "vault_id"),
        UniqueConstraint("id", "owner_id", name="uq_record_owner"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    vault_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("vaults.id", ondelete="CASCADE"), index=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_metadata: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm_version: Mapped[str] = mapped_column(String(32), nullable=False)
    kdf_version: Mapped[int] = mapped_column(Integer, nullable=False)
    record_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    vault: Mapped[Vault] = relationship(back_populates="records")


class Device(Base, TimestampMixin):
    __tablename__ = "devices"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    public_label: Mapped[str] = mapped_column(String(128), nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Session(Base, TimestampMixin):
    __tablename__ = "sessions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    refresh_token_hash: Mapped[str | None] = mapped_column(String(128), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ApiTokenHash(Base, TimestampMixin):
    __tablename__ = "api_token_hashes"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SecurityEvent(Base, TimestampMixin):
    __tablename__ = "security_events"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    request_id: Mapped[str | None] = mapped_column(String(64))
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)


class RecoveryConfiguration(Base, TimestampMixin):
    __tablename__ = "recovery_configurations"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    encrypted_recovery_material: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm_version: Mapped[str] = mapped_column(String(32), nullable=False)


class PendingClientAction(Base, TimestampMixin):
    __tablename__ = "pending_client_actions"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RateLimitState(Base, TimestampMixin):
    __tablename__ = "rate_limit_state"
    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class DeletedAccountTombstone(Base, TimestampMixin):
    __tablename__ = "deleted_account_tombstones"
    discord_user_id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    deleted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(128))


class MfaFactor(Base, TimestampMixin):
    __tablename__ = "mfa_factors"
    __table_args__ = (Index("ix_mfa_factors_user_type_status", "user_id", "factor_type", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    factor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    security_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class TotpFactor(Base, TimestampMixin):
    __tablename__ = "totp_factors"

    factor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("mfa_factors.id", ondelete="CASCADE"), primary_key=True
    )
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="SHA1")
    digits: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    period: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    last_accepted_counter: Mapped[int | None] = mapped_column(Integer)


class PendingTotpEnrollment(Base, TimestampMixin):
    __tablename__ = "pending_totp_enrollments"
    __table_args__ = (Index("ix_pending_totp_user_status", "user_id", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    factor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("mfa_factors.id", ondelete="SET NULL"))
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_key_version: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="SHA1")
    digits: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    period: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebAuthnCredential(Base, TimestampMixin):
    __tablename__ = "webauthn_credentials"
    __table_args__ = (UniqueConstraint("credential_id", name="uq_webauthn_credential_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    factor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("mfa_factors.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[str] = mapped_column(Text, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    user_handle: Mapped[str] = mapped_column(String(128), nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    authenticator_attachment: Mapped[str | None] = mapped_column(String(32))
    backup_eligible: Mapped[bool | None] = mapped_column(Boolean)
    backup_state: Mapped[bool | None] = mapped_column(Boolean)
    transports: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    friendly_name: Mapped[str] = mapped_column(String(128), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RecoveryCode(Base, TimestampMixin):
    __tablename__ = "recovery_codes"
    __table_args__ = (Index("ix_recovery_codes_user_active", "user_id", "consumed_at", "revoked_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    code_hint: Mapped[str] = mapped_column(String(16), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MfaChallenge(Base, TimestampMixin):
    __tablename__ = "mfa_challenges"
    __table_args__ = (Index("ix_mfa_challenges_user_status", "user_id", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    required_assurance: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    request_context_hash: Mapped[str | None] = mapped_column(String(128))
    resource_id: Mapped[str | None] = mapped_column(String(128))


class StepUpGrant(Base, TimestampMixin):
    __tablename__ = "step_up_grants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    assurance_level: Mapped[str] = mapped_column(String(16), nullable=False)
    approved_purposes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TrustedDevice(Base, TimestampMixin):
    __tablename__ = "trusted_devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    platform: Mapped[str | None] = mapped_column(String(128))
    broad_location: Mapped[str | None] = mapped_column(String(128))
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    trust_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_state: Mapped[str] = mapped_column(String(32), nullable=False, default="normal")


class DeviceApproval(Base, TimestampMixin):
    __tablename__ = "device_approvals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    trusted_device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("trusted_devices.id", ondelete="SET NULL"))
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    matching_code: Mapped[str] = mapped_column(String(12), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    signature: Mapped[str | None] = mapped_column(Text)


class MfaAttempt(Base, TimestampMixin):
    __tablename__ = "mfa_attempts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    challenge_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("mfa_challenges.id", ondelete="CASCADE"))
    factor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("mfa_factors.id", ondelete="SET NULL"))
    method: Mapped[str] = mapped_column(String(32), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str | None] = mapped_column(String(64))


class MfaPolicy(Base, TimestampMixin):
    __tablename__ = "mfa_policies"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_for_vault_export: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    require_for_record_reveal: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    security_hold_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
