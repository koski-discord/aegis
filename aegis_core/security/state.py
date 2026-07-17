import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from aegis_core.exceptions import AuthenticationFailed


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign_state(payload: dict[str, Any], key: str, ttl_seconds: int) -> str:
    body = dict(payload)
    body["exp"] = int((datetime.now(UTC) + timedelta(seconds=ttl_seconds)).timestamp())
    encoded = _b64(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64(hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest())
    return f"{encoded}.{sig}"


def verify_state(value: str, key: str) -> dict[str, Any]:
    try:
        encoded, supplied = value.split(".", 1)
    except ValueError as exc:
        raise AuthenticationFailed("invalid state") from exc
    expected = _b64(hmac.new(key.encode(), encoded.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, supplied):
        raise AuthenticationFailed("invalid state")
    payload = cast(dict[str, Any], json.loads(_unb64(encoded)))
    if int(payload["exp"]) < int(datetime.now(UTC).timestamp()):
        raise AuthenticationFailed("expired state")
    return payload
