from enum import StrEnum


class FactorType(StrEnum):
    totp = "totp"
    webauthn = "webauthn"
    recovery_code = "recovery_code"
    trusted_device = "trusted_device"


class FactorStatus(StrEnum):
    pending = "pending"
    active = "active"
    disabled = "disabled"


class TotpEnrollmentStatus(StrEnum):
    not_configured = "not_configured"
    pending = "pending"
    verified = "verified"
    active = "active"
    replacement_pending = "replacement_pending"
    disabled = "disabled"
    canceled = "canceled"
    expired = "expired"


class VerificationPurpose(StrEnum):
    login = "login"
    reveal_vault_record = "reveal_vault_record"
    copy_password = "copy_password"
    export_vault = "export_vault"
    import_vault = "import_vault"
    add_mfa_factor = "add_mfa_factor"
    replace_mfa_factor = "replace_mfa_factor"
    remove_mfa_factor = "remove_mfa_factor"
    generate_recovery_codes = "generate_recovery_codes"
    disable_mfa = "disable_mfa"
    revoke_sessions = "revoke_sessions"
    delete_account = "delete_account"
    change_security_settings = "change_security_settings"


class AssuranceLevel(StrEnum):
    aal1 = "aal1"
    aal2 = "aal2"
    aal3 = "aal3"


class ChallengeStatus(StrEnum):
    pending = "pending"
    completed = "completed"
    consumed = "consumed"
    expired = "expired"
    failed = "failed"


class DeviceApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    expired = "expired"
