import hashlib
import hmac
import secrets
from uuid import UUID

from argon2 import PasswordHasher

from aegis_core.config import Settings

CODE_PREFIX = "AEGIS"
_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16)


def generate_recovery_code() -> str:
    raw = secrets.token_bytes(16)
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    number = int.from_bytes(raw, "big")
    chars = []
    for _ in range(16):
        number, rem = divmod(number, len(alphabet))
        chars.append(alphabet[rem])
    body = "".join(chars)
    groups = "-".join(body[index : index + 4] for index in range(0, len(body), 4))
    return f"{CODE_PREFIX}-{groups}"


def generate_recovery_codes(count: int = 10) -> list[str]:
    return [generate_recovery_code() for _ in range(count)]


def recovery_lookup(code: str, settings: Settings) -> str:
    digest = hmac.new(
        settings.mfa_recovery_code_pepper.get_secret_value().encode(),
        code.encode(),
        hashlib.sha256,
    ).hexdigest()
    return digest


def hash_recovery_code(code: str, settings: Settings) -> str:
    return _HASHER.hash(recovery_lookup(code, settings))


def verify_recovery_code(code: str, encoded_hash: str, settings: Settings) -> bool:
    try:
        return _HASHER.verify(encoded_hash, recovery_lookup(code, settings))
    except Exception:
        return False


def recovery_hint(code: str) -> str:
    return code[-4:]


def recovery_context(user_id: UUID) -> dict[str, str]:
    return {"user_id": str(user_id), "method": "recovery_code"}
