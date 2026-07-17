import base64
import time

import pytest
from nacl.signing import SigningKey

from aegis_core.exceptions import AuthenticationFailed
from aegis_core.security.signing import SignedRequest, verify_signed_request


def make_signed_request(key: SigningKey, key_id: str = "bot") -> tuple[SignedRequest, dict[str, str]]:
    public_keys = {key_id: base64.b64encode(bytes(key.verify_key)).decode()}
    request = SignedRequest(
        key_id=key_id,
        timestamp=int(time.time()),
        nonce="nonce",
        method="POST",
        path="/api/v1/internal/action",
        body=b'{"ok":true}',
        signature="",
    )
    signature = base64.b64encode(key.sign(request.canonical()).signature).decode()
    return request.__class__(**{**request.__dict__, "signature": signature}), public_keys


def test_valid_signed_request() -> None:
    request, public_keys = make_signed_request(SigningKey.generate())

    verify_signed_request(request, public_keys)


def test_tampered_body_rejected() -> None:
    request, public_keys = make_signed_request(SigningKey.generate())
    tampered = request.__class__(**{**request.__dict__, "body": b'{"ok":false}'})

    with pytest.raises(AuthenticationFailed):
        verify_signed_request(tampered, public_keys)


def test_expired_timestamp_rejected() -> None:
    request, public_keys = make_signed_request(SigningKey.generate())
    expired = request.__class__(**{**request.__dict__, "timestamp": 1})

    with pytest.raises(AuthenticationFailed):
        verify_signed_request(expired, public_keys)
