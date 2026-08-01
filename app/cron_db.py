"""Database helpers for the cron job.

All operations here use the Supabase **service-role key**, which bypasses
Row-Level Security and lets the cron read every domain across all users.
The service key must NEVER be used on user-facing endpoints.
"""

from typing import Any

import httpx

from app.config import Settings


def _service_headers(settings: Settings, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Headers that authenticate as the service role, bypassing RLS."""
    base = {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
        "Content-Type": "application/json",
    }
    if extra:
        base.update(extra)
    return base


async def get_all_tracked_domains(settings: Settings) -> list[str]:
    """Return a deduplicated, sorted list of every domain name in the system.

    Paginates through tracked_domains with a page size of 1000 to handle
    large installations.  Uses the service key to bypass RLS.
    """
    base = settings.supabase_url.rstrip("/")
    all_domains: set[str] = set()
    offset = 0
    page_size = 1000

    async with httpx.AsyncClient(timeout=30.0) as client:
        while True:
            resp = await client.get(
                f"{base}/rest/v1/tracked_domains",
                headers=_service_headers(settings),
                params={
                    "select": "domain",
                    "limit": str(page_size),
                    "offset": str(offset),
                },
            )
            resp.raise_for_status()
            rows: list[dict[str, Any]] = resp.json()
            for row in rows:
                all_domains.add(row["domain"])
            if len(rows) < page_size:
                break
            offset += page_size

    return sorted(all_domains)


async def upsert_whois_as_service(
    settings: Settings,
    domain: str,
    raw: str,
    parsed: dict[str, Any],
    fetched_at: str,
) -> None:
    """Upsert a WHOIS record using the service key (no user context needed)."""
    from datetime import datetime, timezone

    base = settings.supabase_url.rstrip("/")
    async with httpx.AsyncClient(timeout=settings.health_check_timeout) as client:
        resp = await client.post(
            f"{base}/rest/v1/domain_whois",
            headers=_service_headers(
                settings,
                {"Prefer": "return=minimal,resolution=merge-duplicates"},
            ),
            json={
                "domain": domain,
                "raw": raw,
                "parsed": parsed,
                "fetched_at": fetched_at,
            },
        )
        resp.raise_for_status()
