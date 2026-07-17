"""aegis verify mfa schema

Revision ID: 0002_aegis_verify
Revises: 0001_initial
Create Date: 2026-07-17
"""
# mypy: ignore-errors

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_aegis_verify"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def uuid_pk() -> sa.Column[sa.UUID]:
    return sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True)


def timestamps() -> list[sa.Column[sa.DateTime]]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    ]


def upgrade() -> None:
    op.create_table(
        "mfa_factors",
        uuid_pk(),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("factor_type", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
        sa.Column("security_version", sa.Integer(), nullable=False, server_default="1"),
        *timestamps(),
    )
    op.create_index("ix_mfa_factors_user_id", "mfa_factors", ["user_id"])
    op.create_index("ix_mfa_factors_user_type_status", "mfa_factors", ["user_id", "factor_type", "status"])
    op.create_table(
        "totp_factors",
        sa.Column(
            "factor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mfa_factors.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("encryption_key_version", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False, server_default="SHA1"),
        sa.Column("digits", sa.Integer(), nullable=False, server_default="6"),
        sa.Column("period", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("last_accepted_counter", sa.Integer()),
        *timestamps(),
    )
    op.create_table(
        "pending_totp_enrollments",
        uuid_pk(),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("factor_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("mfa_factors.id", ondelete="SET NULL")),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("encryption_key_version", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(16), nullable=False, server_default="SHA1"),
        sa.Column("digits", sa.Integer(), nullable=False, server_default="6"),
        sa.Column("period", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.Column("canceled_at", sa.DateTime(timezone=True)),
        *timestamps(),
    )
    op.create_index("ix_pending_totp_enrollments_user_id", "pending_totp_enrollments", ["user_id"])
    op.create_index("ix_pending_totp_user_status", "pending_totp_enrollments", ["user_id", "status"])
    op.create_table(
        "webauthn_credentials",
        uuid_pk(),
        sa.Column(
            "factor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("mfa_factors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("credential_id", sa.Text(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("user_handle", sa.String(128), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("authenticator_attachment", sa.String(32)),
        sa.Column("backup_eligible", sa.Boolean()),
        sa.Column("backup_state", sa.Boolean()),
        sa.Column("transports", postgresql.JSONB(), nullable=False),
        sa.Column("friendly_name", sa.String(128), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        *timestamps(),
        sa.UniqueConstraint("credential_id", name="uq_webauthn_credential_id"),
    )
    op.create_index("ix_webauthn_credentials_user_id", "webauthn_credentials", ["user_id"])
    op.create_index("ix_webauthn_credentials_factor_id", "webauthn_credentials", ["factor_id"])
    op.create_table(
        "recovery_codes",
        uuid_pk(),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("code_hash", sa.String(256), nullable=False, unique=True),
        sa.Column("code_hint", sa.String(16), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        *timestamps(),
    )
    op.create_index("ix_recovery_codes_user_id", "recovery_codes", ["user_id"])
    op.create_index("ix_recovery_codes_user_active", "recovery_codes", ["user_id", "consumed_at", "revoked_at"])
    op.create_table(
        "mfa_challenges",
        uuid_pk(),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sessions.id", ondelete="CASCADE")),
        sa.Column("purpose", sa.String(64), nullable=False),
        sa.Column("required_assurance", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("request_context_hash", sa.String(128)),
        sa.Column("resource_id", sa.String(128)),
        *timestamps(),
    )
    op.create_index("ix_mfa_challenges_user_id", "mfa_challenges", ["user_id"])
    op.create_index("ix_mfa_challenges_user_status", "mfa_challenges", ["user_id", "status"])
    op.create_table(
        "step_up_grants",
        uuid_pk(),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sessions.id", ondelete="CASCADE")),
        sa.Column("assurance_level", sa.String(16), nullable=False),
        sa.Column("approved_purposes", postgresql.JSONB(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        *timestamps(),
    )
    op.create_index("ix_step_up_grants_user_id", "step_up_grants", ["user_id"])
    op.create_table(
        "trusted_devices",
        uuid_pk(),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("platform", sa.String(128)),
        sa.Column("broad_location", sa.String(128)),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("trust_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("risk_state", sa.String(32), nullable=False, server_default="normal"),
        *timestamps(),
    )
    op.create_index("ix_trusted_devices_user_id", "trusted_devices", ["user_id"])
    op.create_table(
        "device_approvals",
        uuid_pk(),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "trusted_device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("trusted_devices.id", ondelete="SET NULL")
        ),
        sa.Column("action_type", sa.String(64), nullable=False),
        sa.Column("matching_code", sa.String(12), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("rejected_at", sa.DateTime(timezone=True)),
        sa.Column("signature", sa.Text()),
        *timestamps(),
    )
    op.create_index("ix_device_approvals_user_id", "device_approvals", ["user_id"])
    op.create_table(
        "mfa_attempts",
        uuid_pk(),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE")),
        sa.Column(
            "challenge_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("mfa_challenges.id", ondelete="CASCADE")
        ),
        sa.Column("factor_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("mfa_factors.id", ondelete="SET NULL")),
        sa.Column("method", sa.String(32), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reason", sa.String(64)),
        *timestamps(),
    )
    op.create_index("ix_mfa_attempts_user_id", "mfa_attempts", ["user_id"])
    op.create_table(
        "mfa_policies",
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_for_vault_export", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("require_for_record_reveal", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("security_hold_until", sa.DateTime(timezone=True)),
        *timestamps(),
    )


def downgrade() -> None:
    for table in [
        "mfa_policies",
        "mfa_attempts",
        "device_approvals",
        "trusted_devices",
        "step_up_grants",
        "mfa_challenges",
        "recovery_codes",
        "webauthn_credentials",
        "pending_totp_enrollments",
        "totp_factors",
        "mfa_factors",
    ]:
        op.drop_table(table)
