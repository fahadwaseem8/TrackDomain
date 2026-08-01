import time

import httpx

from app.config import Settings


def _result(status: str, started: float, detail: str | None = None) -> dict[str, object]:
    return {
        "status": status,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        "detail": detail,
    }


def _classify(response: httpx.Response, started: float) -> dict[str, object] | None:
    """Map an error response to a health result, or None if the response was healthy."""
    if response.status_code in (401, 403):
        return _result(
            "unauthorized",
            started,
            f"Supabase rejected the key (HTTP {response.status_code})",
        )
    if response.status_code >= 400:
        return _result("error", started, f"HTTP {response.status_code}")
    return None


async def check_supabase(settings: Settings) -> dict[str, object]:
    """Verify that the Supabase project is reachable and the configured key is accepted.

    Probes `/auth/v1/health` rather than the PostgREST root: `/rest/v1/` is
    restricted to *secret* keys, so it 401s under a publishable key even when
    the project is perfectly healthy. `/auth/v1/health` works with either.

    If `SUPABASE_HEALTH_TABLE` is set, additionally issues a 1-row read against
    that table, which exercises the actual Postgres path the app depends on.
    """
    if not settings.supabase_url or not settings.supabase_key:
        return {
            "status": "not_configured",
            "latency_ms": None,
            "detail": "SUPABASE_URL / SUPABASE_KEY are not set",
        }

    base = settings.supabase_url.rstrip("/")
    headers = {
        "apikey": settings.supabase_key,
        "Authorization": f"Bearer {settings.supabase_key}",
    }

    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=settings.health_check_timeout) as client:
            response = await client.get(f"{base}/auth/v1/health", headers=headers)

            if (failure := _classify(response, started)) is not None:
                return failure

            if settings.supabase_health_table:
                table_response = await client.get(
                    f"{base}/rest/v1/{settings.supabase_health_table}",
                    headers=headers,
                    params={"select": "*", "limit": 1},
                )
                if table_response.status_code == 404:
                    return _result(
                        "error",
                        started,
                        f"Table '{settings.supabase_health_table}' not found",
                    )
                if (failure := _classify(table_response, started)) is not None:
                    return failure

    except httpx.TimeoutException:
        return _result(
            "timeout",
            started,
            f"No response within {settings.health_check_timeout}s",
        )
    except httpx.HTTPError as exc:
        return _result("unreachable", started, f"{type(exc).__name__}: {exc}")

    return _result("ok", started)
