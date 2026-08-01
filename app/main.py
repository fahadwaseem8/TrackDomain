from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.api import auth, cron, domains, health
from app.config import Settings, get_settings

settings = get_settings()


# OpenAPI docs — hide in production by setting DOCS_ENABLED=false
# ---------------------------------------------------------------------------
app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="A domain tracking and monitoring API.",
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
)


# ---------------------------------------------------------------------------
# Security-headers middleware
# ---------------------------------------------------------------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject security-related HTTP response headers on every reply.

    These don't help for a pure JSON API the way they would for an HTML app,
    but they prevent downgrade attacks and info leakage if someone ever points
    a browser (or a misconfigured fetch client) directly at this service.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        # Prevent intermediary caches from storing auth responses.
        response.headers["Cache-Control"] = "no-store"
        # Remove the Server header that uvicorn adds by default —
        # there's no need to advertise which software stack we run.
        if "server" in response.headers:
            del response.headers["server"]
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ---------------------------------------------------------------------------
# CORS — only applied when CORS_ALLOWED_ORIGINS is set in .env
# ---------------------------------------------------------------------------
if settings.cors_allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Retry-After"],
    )


# ---------------------------------------------------------------------------
# Request fields whose submitted value must never appear in an error response.
# ---------------------------------------------------------------------------
SENSITIVE_FIELDS = {"password", "access_token", "refresh_token", "token"}


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    """Strip submitted values for sensitive fields out of 422 bodies.

    FastAPI's default handler echoes the offending input back to the caller, so a
    password that fails the length check would be reflected into access logs,
    proxies, and error trackers.
    """
    errors = []
    for error in exc.errors():
        error = dict(error)
        if any(field in SENSITIVE_FIELDS for field in error.get("loc", ())):
            error.pop("input", None)
        errors.append(error)

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=jsonable_encoder({"detail": errors}),
    )


app.include_router(health.router)
app.include_router(auth.router)
app.include_router(domains.router)
app.include_router(cron.router)
