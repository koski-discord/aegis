import base64
import json
import os
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis_core.config import Settings


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _key(settings: Settings, key_id: str) -> bytes:
    encoded = settings.mfa_encryption_keys[key_id].get_secret_value()
    key = _unb64(encoded)
    if len(key) != 32:
        raise RuntimeError("MFA encryption keys must decode to 32 bytes")
    return key


def associated_data(user_id: UUID, factor_id: UUID | None, factor_type: str, version: str = "v1") -> bytes:
    return json.dumps(
        {
            "user_id": str(user_id),
            "factor_id": str(factor_id) if factor_id else None,
            "factor_type": factor_type,
            "version": version,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def encrypt_mfa_secret(
    *,
    plaintext: str,
    settings: Settings,
    user_id: UUID,
    factor_id: UUID | None,
    factor_type: str,
) -> tuple[str, str, str]:
    key_id = settings.mfa_current_key_id
    kek = _key(settings, key_id)
    dek = os.urandom(32)
    nonce = os.urandom(12)
    wrap_nonce = os.urandom(12)
    aad = associated_data(user_id, factor_id, factor_type)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext.encode(), aad)
    wrapped_dek = AESGCM(kek).encrypt(wrap_nonce, dek, aad)
    payload = {
        "ciphertext": _b64(ciphertext),
        "wrapped_dek": _b64(wrapped_dek),
        "wrap_nonce": _b64(wrap_nonce),
        "version": "v1",
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True), _b64(nonce), key_id


def decrypt_mfa_secret(
    *,
    encrypted_secret: str,
    nonce: str,
    key_id: str,
    settings: Settings,
    user_id: UUID,
    factor_id: UUID | None,
    factor_type: str,
) -> str:
    payload: dict[str, Any] = json.loads(encrypted_secret)
    aad = associated_data(user_id, factor_id, factor_type, str(payload["version"]))
    kek = _key(settings, key_id)
    dek = AESGCM(kek).decrypt(_unb64(str(payload["wrap_nonce"])), _unb64(str(payload["wrapped_dek"])), aad)
    plaintext = AESGCM(dek).decrypt(_unb64(nonce), _unb64(str(payload["ciphertext"])), aad)
    return plaintext.decode()
