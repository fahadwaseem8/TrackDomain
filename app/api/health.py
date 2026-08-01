from fastapi import APIRouter, Depends, Response, status
from pydantic import BaseModel

from app.config import Settings, get_settings
from app.db import check_supabase

router = APIRouter(tags=["health"])


class DependencyHealth(BaseModel):
    status: str
    latency_ms: float | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    database: DependencyHealth


@router.get(
    "/",
    response_model=HealthResponse,
    summary="Health check",
    responses={503: {"model": HealthResponse, "description": "A dependency is unhealthy"}},
)
async def health(
    response: Response,
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    """Report API status along with live Supabase connectivity."""
    database = DependencyHealth(**await check_supabase(settings))

    healthy = database.status == "ok"
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status="ok" if healthy else "degraded",
        app=settings.app_name,
        version=settings.version,
        environment=settings.environment,
        database=database,
    )
