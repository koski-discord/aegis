import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta


def new_token(byte_count: int = 32) -> str:
    return secrets.token_urlsafe(byte_count)


def hash_token(token: str, key: str) -> str:
    digest = hmac.new(key.encode(), token.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def expires_at(seconds: int) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=seconds)


def utcnow() -> datetime:
    return datetime.now(UTC)
