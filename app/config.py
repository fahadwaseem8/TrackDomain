from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, loaded from environment variables / `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "TrackDomain"
    version: str = "0.1.0"
    environment: str = "development"
    debug: bool = True

    supabase_url: str = ""
    supabase_key: str = ""

    # Seconds to wait on the Supabase ping before calling it unhealthy.
    health_check_timeout: float = 3.0

    # Optional: a table to read 1 row from during the health check, so the
    # check exercises the real Postgres path and not just auth reachability.
    supabase_health_table: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
