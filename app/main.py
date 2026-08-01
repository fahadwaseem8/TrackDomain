from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import auth, health
from app.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="A domain tracking and monitoring API.",
)

# Request fields whose submitted value must never appear in an error response.
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


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"app": settings.app_name, "docs": "/docs", "health": "/health"}
