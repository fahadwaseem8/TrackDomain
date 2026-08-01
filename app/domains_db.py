"""PostgREST data-access layer for the tracked_domains table.

We pass the caller's JWT as the Bearer token on every request so Postgres
Row-Level Security runs under the right identity — the database enforces
ownership, we never need to filter by user_id in application code.
"""

from typing import Any

import httpx

from app.config import Settings


class DomainDBError(Exception):
    """A PostgREST call failed. `status_code` maps to the HTTP response to return."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _rest_url(settings: Settings, path: str) -> str:
    return f"{settings.supabase_url.rstrip('/')}/rest/v1{path}"


def _headers(settings: Settings, user_jwt: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    base = {
        "apikey": settings.supabase_key,
        "Authorization": f"Bearer {user_jwt}",
        "Content-Type": "application/json",
    }
    if extra:
        base.update(extra)
    return base


async def _request(
    method: str,
    url: str,
    headers: dict[str, str],
    timeout: float,
    **kwargs: Any,
) -> httpx.Response:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await client.request(method, url, headers=headers, **kwargs)
    except httpx.TimeoutException:
        raise DomainDBError(504, "Database request timed out") from None
    except httpx.HTTPError as exc:
        raise DomainDBError(503, f"Database unreachable: {exc}") from exc


async def list_domains(settings: Settings, user_jwt: str) -> list[dict[str, Any]]:
    """Return all tracked domains for the authenticated user, newest first."""
    resp = await _request(
        "GET",
        _rest_url(settings, "/tracked_domains"),
        headers=_headers(settings, user_jwt),
        timeout=settings.health_check_timeout,
        params={"select": "id,domain,created_at", "order": "created_at.desc"},
    )
    if resp.status_code == 401:
        raise DomainDBError(401, "Unauthorized")
    if resp.status_code >= 400:
        raise DomainDBError(502, f"Database error (HTTP {resp.status_code})")
    return resp.json()


async def add_domain(
    settings: Settings,
    user_jwt: str,
    domain: str,
    user_id: str,
) -> dict[str, Any]:
    """Insert a domain and return the created row.

    Raises DomainDBError(409) if the user already tracks this domain.
    """
    resp = await _request(
        "POST",
        _rest_url(settings, "/tracked_domains"),
        headers=_headers(settings, user_jwt, {"Prefer": "return=representation"}),
        timeout=settings.health_check_timeout,
        json={"domain": domain, "user_id": user_id},
    )
    if resp.status_code == 409:
        raise DomainDBError(409, f"'{domain}' is already in your tracking list")
    if resp.status_code == 401:
        raise DomainDBError(401, "Unauthorized")
    if resp.status_code >= 400:
        raise DomainDBError(502, f"Database error (HTTP {resp.status_code})")

    rows = resp.json()
    return rows[0] if isinstance(rows, list) else rows


async def remove_domain(
    settings: Settings,
    user_jwt: str,
    domain_id: str,
) -> bool:
    """Delete a domain row by id. Returns True if a row was deleted, False if not found.

    RLS ensures the user can only delete their own rows, so a 204 with no rows
    affected safely means 'not found (or not yours)'.
    """
    resp = await _request(
        "DELETE",
        _rest_url(settings, "/tracked_domains"),
        headers=_headers(settings, user_jwt, {"Prefer": "return=representation"}),
        timeout=settings.health_check_timeout,
        params={"id": f"eq.{domain_id}"},
    )
    if resp.status_code == 401:
        raise DomainDBError(401, "Unauthorized")
    if resp.status_code >= 400:
        raise DomainDBError(502, f"Database error (HTTP {resp.status_code})")

    # PostgREST returns the deleted rows; empty list = not found / not yours
    deleted = resp.json() if resp.content else []
    return bool(deleted)


async def get_domain_by_id(
    settings: Settings,
    user_jwt: str,
    domain_id: str,
) -> dict[str, Any] | None:
    """Return a single tracked-domain row by its UUID for the authenticated user.

    Returns None if not found or if RLS hides the row (i.e. it belongs to
    someone else).  The caller treats both cases as 404.
    """
    resp = await _request(
        "GET",
        _rest_url(settings, "/tracked_domains"),
        headers=_headers(settings, user_jwt),
        timeout=settings.health_check_timeout,
        params={
            "select": "id,domain",
            "id": f"eq.{domain_id}",
            "limit": "1",
        },
    )
    if resp.status_code == 401:
        raise DomainDBError(401, "Unauthorized")
    if resp.status_code >= 400:
        raise DomainDBError(502, f"Database error (HTTP {resp.status_code})")
    rows = resp.json()
    return rows[0] if rows else None

