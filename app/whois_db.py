"""PostgREST data-access layer for the domain_whois table.

WHOIS data is shared across all users who track the same domain.
We reuse the helpers from domains_db for consistency.
"""

from datetime import datetime, timezone
from typing import Any

from app.config import Settings
from app.domains_db import DomainDBError, _headers, _request, _rest_url


async def get_whois(settings: Settings, user_jwt: str, domain: str) -> dict[str, Any] | None:
    """Return the cached WHOIS record for *domain*, or None if not yet fetched."""
    resp = await _request(
        "GET",
        _rest_url(settings, "/domain_whois"),
        headers=_headers(settings, user_jwt),
        timeout=settings.health_check_timeout,
        params={
            "select": "domain,raw,parsed,fetched_at",
            "domain": f"eq.{domain}",
            "limit": "1",
        },
    )
    if resp.status_code == 401:
        raise DomainDBError(401, "Unauthorized")
    if resp.status_code >= 400:
        raise DomainDBError(502, f"Database error (HTTP {resp.status_code})")
    rows = resp.json()
    return rows[0] if rows else None


async def upsert_whois(
    settings: Settings,
    user_jwt: str,
    domain: str,
    raw: str,
    parsed: dict[str, Any],
) -> dict[str, Any]:
    """Insert or replace the WHOIS record for *domain*.

    On conflict (domain already exists) all columns are updated, so the
    latest fetch always wins.  ``fetched_at`` is set to the current UTC
    time from Python so it reflects the actual fetch time, not the DB
    commit time.
    """
    resp = await _request(
        "POST",
        _rest_url(settings, "/domain_whois"),
        headers=_headers(
            settings,
            user_jwt,
            {
                # return=representation: give us the upserted row back
                # resolution=merge-duplicates: ON CONFLICT DO UPDATE
                "Prefer": "return=representation,resolution=merge-duplicates",
            },
        ),
        timeout=settings.health_check_timeout,
        json={
            "domain": domain,
            "raw": raw,
            "parsed": parsed,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    if resp.status_code == 401:
        raise DomainDBError(401, "Unauthorized")
    if resp.status_code >= 400:
        raise DomainDBError(502, f"Database error (HTTP {resp.status_code})")
    rows = resp.json()
    return rows[0] if isinstance(rows, list) else rows
