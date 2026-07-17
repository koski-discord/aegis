import base64
import uuid

import pyotp
import pytest
from fastapi.testclient import TestClient

from aegis_core.config import get_settings
from aegis_core.security.mfa import AssuranceLevel, FactorType, VerificationPurpose
from apps.api.main import create_app
from apps.api.schemas.mfa import MfaChallengeCreate, TotpEnrollmentStart
from apps.api.services.mfa import create_webauthn_options
from apps.api.services.mfa_crypto import decrypt_mfa_secret, encrypt_mfa_secret
from apps.api.services.mfa_policy import MfaPolicyEngine
from apps.api.services.recovery_codes import (
    generate_recovery_codes,
    hash_recovery_code,
    verify_recovery_code,
)
from apps.api.services.totp import (
    create_totp_enrollment_material,
    qr_png,
    verify_totp_code,
)

RFC6238_SECRET = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize(
    ("timestamp", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_rfc_6238_sha1_vectors(timestamp: int, expected: str) -> None:
    totp = pyotp.TOTP(RFC6238_SECRET, digits=8, interval=30, digest="sha1")

    assert totp.at(timestamp) == expected


def test_valid_totp_and_replay_rejection() -> None:
    secret = pyotp.random_base32(length=32)
    code = pyotp.TOTP(secret).at(1_800)

    ok, counter = verify_totp_code(secret=secret, code=code, last_accepted_counter=None, for_time=1_800)
    replay_ok, _ = verify_totp_code(
        secret=secret,
        code=code,
        last_accepted_counter=counter,
        for_time=1_800,
    )

    assert ok is True
    assert counter == 60
    assert replay_ok is False


def test_totp_rejects_expired_and_malformed_codes() -> None:
    secret = pyotp.random_base32(length=32)
    old_code = pyotp.TOTP(secret).at(1_200)

    ok, _ = verify_totp_code(secret=secret, code=old_code, last_accepted_counter=None, for_time=1_800)
    spaced, _ = verify_totp_code(secret=secret, code=f" {old_code[-6:]}", last_accepted_counter=None, for_time=1_800)

    assert ok is False
    assert spaced is False


def test_totp_allows_small_clock_skew_boundary() -> None:
    secret = pyotp.random_base32(length=32)
    previous_step_code = pyotp.TOTP(secret).at(1_770)

    ok, counter = verify_totp_code(
        secret=secret,
        code=previous_step_code,
        last_accepted_counter=None,
        for_time=1_800,
        valid_window=1,
    )

    assert ok is True
    assert counter == 59


def test_mfa_secret_encryption_round_trip() -> None:
    settings = get_settings()
    user_id = uuid.uuid4()
    factor_id = uuid.uuid4()

    encrypted, nonce, key_id = encrypt_mfa_secret(
        plaintext="SECRET",
        settings=settings,
        user_id=user_id,
        factor_id=factor_id,
        factor_type=FactorType.totp,
    )

    assert "SECRET" not in encrypted
    assert (
        decrypt_mfa_secret(
            encrypted_secret=encrypted,
            nonce=nonce,
            key_id=key_id,
            settings=settings,
            user_id=user_id,
            factor_id=factor_id,
            factor_type=FactorType.totp,
        )
        == "SECRET"
    )


def test_totp_enrollment_material_contains_standard_uri_and_qr() -> None:
    material = create_totp_enrollment_material(get_settings(), uuid.uuid4())

    assert material.provisioning_uri.startswith("otpauth://totp/Aegis%3A")
    assert "issuer=Aegis" in material.provisioning_uri
    assert "algorithm=SHA1" in material.provisioning_uri
    assert qr_png(material.provisioning_uri).startswith(b"\x89PNG")


def test_recovery_codes_are_hashed_and_single_use_verifiable() -> None:
    settings = get_settings()
    codes = generate_recovery_codes()
    encoded_hash = hash_recovery_code(codes[0], settings)

    assert len(codes) == 10
    assert codes[0] not in encoded_hash
    assert verify_recovery_code(codes[0], encoded_hash, settings) is True
    assert verify_recovery_code(codes[1], encoded_hash, settings) is False


def test_mfa_policy_for_export_requires_aal2() -> None:
    decision = MfaPolicyEngine().evaluate(VerificationPurpose.export_vault)

    assert decision.step_up_required is True
    assert decision.minimum_assurance == AssuranceLevel.aal2
    assert FactorType.totp in decision.allowed_factor_types


def test_webauthn_options_use_standard_shape() -> None:
    user = type("UserStub", (), {"id": uuid.uuid4(), "discord_user_id": 123456789})()

    challenge, options = create_webauthn_options(get_settings(), user, "registration")

    assert len(challenge) > 20
    assert options["rp"]["name"] == "Aegis"
    assert options["challenge"] == challenge


def test_mfa_schemas_reject_secret_fields() -> None:
    with pytest.raises(ValueError):
        TotpEnrollmentStart.model_validate({"display_name": "Phone", "totp_secret": "SHOULD-NOT-BE-HERE"})
    with pytest.raises(ValueError):
        MfaChallengeCreate.model_validate({"purpose": "login", "recovery_code": "SHOULD-NOT-BE-HERE"})


def test_verify_dashboard_has_no_store_headers() -> None:
    response = TestClient(create_app()).get("/verify")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
