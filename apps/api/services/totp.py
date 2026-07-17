import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from io import BytesIO
from urllib.parse import quote
from uuid import UUID

import pyotp
import qrcode

from aegis_core.config import Settings
from aegis_core.security.mfa import FactorType
from apps.api.services.mfa_crypto import decrypt_mfa_secret, encrypt_mfa_secret

TOTP_CODE_RE = re.compile(r"^[0-9]{6}$")


@dataclass(frozen=True)
class TotpEnrollmentMaterial:
    secret: str
    encrypted_secret: str
    nonce: str
    key_id: str
    provisioning_uri: str
    expires_at: datetime


def account_label(user_id: UUID) -> str:
    return f"Aegis:{str(user_id)[:8]}"


def generate_totp_secret() -> str:
    return pyotp.random_base32(length=32)


def provisioning_uri(secret: str, user_id: UUID) -> str:
    issuer = "Aegis"
    label = account_label(user_id)
    return (
        f"otpauth://totp/{quote(label)}?secret={quote(secret)}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )


def create_totp_enrollment_material(settings: Settings, user_id: UUID) -> TotpEnrollmentMaterial:
    secret = generate_totp_secret()
    encrypted, nonce, key_id = encrypt_mfa_secret(
        plaintext=secret,
        settings=settings,
        user_id=user_id,
        factor_id=None,
        factor_type=FactorType.totp.value,
    )
    return TotpEnrollmentMaterial(
        secret=secret,
        encrypted_secret=encrypted,
        nonce=nonce,
        key_id=key_id,
        provisioning_uri=provisioning_uri(secret, user_id),
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
    )


def decrypt_totp_secret(
    settings: Settings,
    *,
    encrypted_secret: str,
    nonce: str,
    key_id: str,
    user_id: UUID,
    factor_id: UUID | None = None,
) -> str:
    return decrypt_mfa_secret(
        encrypted_secret=encrypted_secret,
        nonce=nonce,
        key_id=key_id,
        settings=settings,
        user_id=user_id,
        factor_id=factor_id,
        factor_type=FactorType.totp.value,
    )


def validate_totp_code_format(code: str) -> bool:
    return bool(TOTP_CODE_RE.fullmatch(code))


def time_counter(for_time: int | None = None, period: int = 30) -> int:
    return int((time.time() if for_time is None else for_time) // period)


def verify_totp_code(
    *,
    secret: str,
    code: str,
    last_accepted_counter: int | None,
    for_time: int | None = None,
    valid_window: int = 1,
    digits: int = 6,
    period: int = 30,
) -> tuple[bool, int | None]:
    if not validate_totp_code_format(code):
        return False, None
    totp = pyotp.TOTP(secret, digits=digits, interval=period, digest="sha1")
    now_counter = time_counter(for_time, period)
    for offset in range(-valid_window, valid_window + 1):
        counter = now_counter + offset
        if last_accepted_counter is not None and counter <= last_accepted_counter:
            continue
        if totp.verify(code, for_time=datetime.fromtimestamp(counter * period, UTC), valid_window=0):
            return True, counter
    return False, None


def qr_png(provisioning_uri_value: str) -> bytes:
    image = qrcode.make(provisioning_uri_value)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
