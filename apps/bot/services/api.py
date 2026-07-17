import base64
import hashlib
import json
import secrets
import time
from typing import Any

import httpx
from nacl.signing import SigningKey


class SignedApiClient:
    def __init__(
        self,
        base_url: str,
        *,
        key_id: str,
        private_key_b64: str,
        timeout: float = 8.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.key_id = key_id
        self.signing_key = SigningKey(base64.b64decode(private_key_b64)) if private_key_b64 else None
        self.timeout = timeout

    def _headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        if self.signing_key is None:
            return {}
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(18)
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = "\n".join([self.key_id, timestamp, nonce, method.upper(), path, body_hash]).encode()
        signature = base64.b64encode(self.signing_key.sign(canonical).signature).decode()
        return {
            "x-aegis-key-id": self.key_id,
            "x-aegis-timestamp": timestamp,
            "x-aegis-nonce": nonce,
            "x-aegis-signature": signature,
        }

    async def post_internal(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode()
        headers = self._headers("POST", path, body)
        headers["content-type"] = "application/json"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(f"{self.base_url}{path}", content=body, headers=headers)
            response.raise_for_status()
            return dict(response.json())
