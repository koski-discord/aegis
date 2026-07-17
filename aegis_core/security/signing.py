import base64
import hashlib
import time
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from aegis_core.exceptions import AuthenticationFailed


@dataclass(frozen=True)
class SignedRequest:
    key_id: str
    timestamp: int
    nonce: str
    method: str
    path: str
    body: bytes
    signature: str

    def canonical(self) -> bytes:
        body_hash = hashlib.sha256(self.body).hexdigest()
        return "\n".join(
            [
                self.key_id,
                str(self.timestamp),
                self.nonce,
                self.method.upper(),
                self.path,
                body_hash,
            ]
        ).encode()


def verify_signed_request(
    request: SignedRequest,
    public_keys: dict[str, str],
    *,
    now: int | None = None,
    max_skew_seconds: int = 300,
) -> None:
    current = int(time.time()) if now is None else now
    if abs(current - request.timestamp) > max_skew_seconds:
        raise AuthenticationFailed("invalid service authentication")
    encoded_key = public_keys.get(request.key_id)
    if encoded_key is None:
        raise AuthenticationFailed("invalid service authentication")
    try:
        key = VerifyKey(base64.b64decode(encoded_key))
        key.verify(request.canonical(), base64.b64decode(request.signature))
    except (BadSignatureError, ValueError) as exc:
        raise AuthenticationFailed("invalid service authentication") from exc
