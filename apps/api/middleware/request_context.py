import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get("x-request-id", uuid.uuid4().hex)
        correlation_id = request.headers.get("x-correlation-id", request_id)
        request.state.request_id = request_id
        with structlog.contextvars.bound_contextvars(
            request_id=request_id, correlation_id=correlation_id, route=str(request.url.path)
        ):
            response = await call_next(request)
        response.headers["x-request-id"] = request_id
        response.headers["x-correlation-id"] = correlation_id
        return response
