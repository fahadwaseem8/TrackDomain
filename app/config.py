from functools import lru_cache
from typing import Annotated

from pydantic import Field
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
    # Set to True only for local dev; never expose tracebacks in production.
    debug: bool = False

    # Comma-separated list of allowed CORS origins, e.g. "https://app.example.com".
    # An empty string disables CORS (same-origin only).
    # Use "*" only for fully public, read-only APIs.
    cors_allowed_origins: Annotated[list[str], Field(default_factory=list)]

    # Set to False to hide /docs and /redoc in production.
    docs_enabled: bool = True

    supabase_url: str = ""
    supabase_key: str = ""

    # Seconds to wait on the Supabase ping before calling it unhealthy.
    health_check_timeout: float = 3.0

    # Optional: a table to read 1 row from during the health check, so the
    # check exercises the real Postgres path and not just auth reachability.
    supabase_health_table: str = ""

    # Seconds to wait for a WHOIS server to respond.
    # WHOIS lookups go through an external server and are often slow.
    whois_timeout: float = 30.0

    # Seconds to sleep between consecutive WHOIS lookups in the cron job.
    # Keeps us polite to WHOIS servers that rate-limit by source IP.
    whois_batch_delay: float = 2.0

    # Supabase service-role key — bypasses RLS and is ONLY used by the
    # cron job to read all domains across all users.  Never expose this
    # key to the client or return it in any response.
    supabase_service_key: str = ""

    # Random secret shared with Vercel.  Vercel sends this as
    # Authorization: Bearer {cron_secret} on every cron invocation.
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    cron_secret: str = ""


    # Seconds to cache the Supabase JWKS before refetching signing keys.
    jwks_cache_ttl: float = 600.0

    # Floor between key-rotation refetches. Without it, a token bearing an
    # unknown `kid` forces an outbound request, letting an attacker turn cheap
    # requests into traffic against Supabase.
    jwks_min_refetch_seconds: float = 60.0

    # Brute-force limits, per (client IP, email) pair. See app/rate_limit.py
    # for why these are per-process and what that means in production.
    login_max_attempts: int = 10
    login_window_seconds: float = 300.0
    signup_max_attempts: int = 5
    signup_window_seconds: float = 3600.0

    @property
    def auth_url(self) -> str:
        """Base URL of the Supabase auth (GoTrue) service."""
        return f"{self.supabase_url.rstrip('/')}/auth/v1"

    @property
    def jwt_issuer(self) -> str:
        """Expected `iss` claim on Supabase-issued access tokens."""
        return self.auth_url


@lru_cache
def get_settings() -> Settings:
    return Settings()
