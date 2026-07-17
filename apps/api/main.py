import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from aegis_core.config import get_settings
from aegis_core.logging import configure_logging
from apps.api.middleware.body_limit import BodySizeLimitMiddleware
from apps.api.middleware.request_context import RequestContextMiddleware
from apps.api.middleware.service_auth import ServiceAuthMiddleware
from apps.api.routes import account, auth, health, security, vault, version


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.service_name, settings.environment)
    app = FastAPI(
        title="Aegis API",
        docs_url="/docs" if settings.docs_enabled and settings.environment != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(ServiceAuthMiddleware, settings=settings)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["authorization", "content-type", "x-request-id", "x-correlation-id"],
    )
    prefix = "/api/v1"
    app.include_router(health.router, prefix=prefix)
    app.include_router(version.router, prefix=prefix)
    app.include_router(auth.router, prefix=prefix)
    app.include_router(vault.router, prefix=prefix)
    app.include_router(security.router, prefix=prefix)
    app.include_router(account.router, prefix=prefix)

    @app.exception_handler(ValueError)
    async def validation_error(_: Request, __: ValueError) -> JSONResponse:
        return JSONResponse({"error": "invalid request"}, status_code=422)

    return app


app = create_app()


def run() -> None:
    uvicorn.run("apps.api.main:app", host="0.0.0.0", port=8000, reload=False)
