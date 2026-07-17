import base64
import json
import os
import secrets
from typing import Any, cast

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from apps.client.models.records import EncryptedPayload, PlainRecord

DEFAULT_KDF_PARAMS: dict[str, int | str] = {
    "algorithm": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4,
    "hash_len": 32,
}


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def new_salt() -> str:
    return b64(os.urandom(16))


def derive_key(master_password: str, salt: str, params: dict[str, int | str] | None = None) -> bytes:
    selected = {**DEFAULT_KDF_PARAMS, **(params or {})}
    if selected.get("algorithm") != "argon2id":
        raise ValueError("unsupported KDF")
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=unb64(salt),
        time_cost=int(selected["time_cost"]),
        memory_cost=int(selected["memory_cost"]),
        parallelism=int(selected["parallelism"]),
        hash_len=int(selected["hash_len"]),
        type=Type.ID,
    )


def _encrypt_json(key: bytes, value: dict[str, Any]) -> tuple[str, str]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(value, separators=(",", ":")).encode(), None)
    return b64(ciphertext), b64(nonce)


def _decrypt_json(key: bytes, ciphertext: str, nonce: str) -> dict[str, Any]:
    try:
        plaintext = AESGCM(key).decrypt(unb64(nonce), unb64(ciphertext), None)
    except InvalidTag as exc:
        raise ValueError("decryption failed") from exc
    return cast(dict[str, Any], json.loads(plaintext))


def encrypt_record(key: bytes, record: PlainRecord) -> EncryptedPayload:
    metadata = {"label": record.label, "url": record.url}
    secret_body = record.model_dump()
    ciphertext, nonce = _encrypt_json(key, secret_body)
    encrypted_metadata, metadata_nonce = _encrypt_json(key, metadata)
    return EncryptedPayload(
        ciphertext=ciphertext,
        nonce=nonce,
        encrypted_metadata=encrypted_metadata,
        metadata_nonce=metadata_nonce,
    )


def decrypt_record(key: bytes, payload: EncryptedPayload) -> PlainRecord:
    decoded = _decrypt_json(key, payload.ciphertext, payload.nonce)
    return PlainRecord.model_validate(decoded)


def generate_recovery_material() -> str:
    return "aegis-recovery-" + secrets.token_urlsafe(32)
