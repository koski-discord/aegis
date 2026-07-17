from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from aegis_core.config import Settings
from aegis_core.exceptions import AuthenticationFailed
from aegis_core.security.signing import SignedRequest, verify_signed_request


class ServiceAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings
        self.seen_nonces: set[str] = set()

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if not request.url.path.startswith("/api/v1/internal/"):
            return await call_next(request)
        body = await request.body()
        signed = SignedRequest(
            key_id=request.headers.get("x-aegis-key-id", ""),
            timestamp=int(request.headers.get("x-aegis-timestamp", "0")),
            nonce=request.headers.get("x-aegis-nonce", ""),
            method=request.method,
            path=request.url.path,
            body=body,
            signature=request.headers.get("x-aegis-signature", ""),
        )
        nonce_key = f"{signed.key_id}:{signed.nonce}"
        try:
            if nonce_key in self.seen_nonces:
                raise AuthenticationFailed("invalid service authentication")
            verify_signed_request(signed, self.settings.bot_signing_public_keys)
        except AuthenticationFailed:
            return JSONResponse({"error": "authentication failed"}, status_code=401)
        self.seen_nonces.add(nonce_key)
        return await call_next(request)
