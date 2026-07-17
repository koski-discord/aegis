from dataclasses import dataclass

from aegis_core.security.mfa import AssuranceLevel, FactorType, VerificationPurpose


@dataclass(frozen=True)
class MfaPolicyDecision:
    step_up_required: bool
    minimum_assurance: AssuranceLevel
    allowed_factor_types: tuple[FactorType, ...]
    challenge_lifetime_seconds: int
    recent_primary_auth_required: bool
    trusted_device_approval_required: bool
    denied: bool = False


class MfaPolicyEngine:
    def evaluate(self, purpose: VerificationPurpose, *, high_risk: bool = False) -> MfaPolicyDecision:
        aal3_purposes = {VerificationPurpose.disable_mfa}
        aal2_purposes = {
            VerificationPurpose.reveal_vault_record,
            VerificationPurpose.copy_password,
            VerificationPurpose.export_vault,
            VerificationPurpose.import_vault,
            VerificationPurpose.add_mfa_factor,
            VerificationPurpose.replace_mfa_factor,
            VerificationPurpose.remove_mfa_factor,
            VerificationPurpose.generate_recovery_codes,
            VerificationPurpose.revoke_sessions,
            VerificationPurpose.delete_account,
            VerificationPurpose.change_security_settings,
        }
        factors: tuple[FactorType, ...]
        if purpose in aal3_purposes or high_risk:
            minimum = AssuranceLevel.aal3
            factors = (FactorType.webauthn, FactorType.totp, FactorType.recovery_code, FactorType.trusted_device)
        elif purpose in aal2_purposes:
            minimum = AssuranceLevel.aal2
            factors = (FactorType.webauthn, FactorType.totp, FactorType.recovery_code)
        else:
            minimum = AssuranceLevel.aal1
            factors = (FactorType.webauthn, FactorType.totp)
        return MfaPolicyDecision(
            step_up_required=minimum != AssuranceLevel.aal1,
            minimum_assurance=minimum,
            allowed_factor_types=factors,
            challenge_lifetime_seconds=300,
            recent_primary_auth_required=minimum != AssuranceLevel.aal1,
            trusted_device_approval_required=high_risk,
        )
