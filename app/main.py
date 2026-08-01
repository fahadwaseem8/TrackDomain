from fastapi import FastAPI

from app.api import auth, health
from app.config import get_settings

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="A domain tracking and monitoring API.",
)

app.include_router(health.router)
app.include_router(auth.router)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"app": settings.app_name, "docs": "/docs", "health": "/health"}
