"""Thin async wrapper over the Supabase Auth (GoTrue) REST API.

Passwords are sent straight to Supabase and never stored or hashed here.
"""

from typing import Any

import httpx

from app.config import Settings


class SupabaseAuthError(Exception):
    """A GoTrue call failed. `status_code` is the HTTP status we should surface."""

    def __init__(self, status_code: int, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.code = code


def _headers(settings: Settings) -> dict[str, str]:
    return {
        "apikey": settings.supabase_key,
        "Content-Type": "application/json",
    }


def _extract_error(response: httpx.Response) -> tuple[str, str | None]:
    """Pull a human-readable message and error code out of a GoTrue error body."""
    try:
        body = response.json()
    except ValueError:
        return response.text.strip() or "Authentication service error", None

    if not isinstance(body, dict):
        return "Authentication service error", None

    message = (
        body.get("error_description")
        or body.get("msg")
        or body.get("message")
        or (body.get("error") if isinstance(body.get("error"), str) else None)
        or "Authentication service error"
    )
    code = body.get("error_code") or body.get("code")
    return message, (code if isinstance(code, str) else None)


async def _post(settings: Settings, path: str, payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    if not settings.supabase_url or not settings.supabase_key:
        raise SupabaseAuthError(503, "Supabase is not configured on this server")

    try:
        async with httpx.AsyncClient(timeout=settings.health_check_timeout) as client:
            response = await client.post(
                f"{settings.auth_url}{path}",
                json=payload,
                headers=_headers(settings),
                **kwargs,
            )
    except httpx.TimeoutException:
        raise SupabaseAuthError(504, "Authentication service timed out") from None
    except httpx.HTTPError as exc:
        raise SupabaseAuthError(503, f"Authentication service unreachable: {exc}") from exc

    if response.is_error:
        message, code = _extract_error(response)
        # GoTrue reports bad credentials as 400; 401 is the correct status for a client.
        status_code = 401 if response.status_code == 400 and code == "invalid_credentials" else response.status_code
        raise SupabaseAuthError(status_code, message, code)

    return response.json()


async def sign_up(settings: Settings, email: str, password: str) -> dict[str, Any]:
    """Register a new user. Returns the created user, plus a session if
    email confirmation is disabled on the project."""
    return await _post(settings, "/signup", {"email": email, "password": password})


async def sign_in(settings: Settings, email: str, password: str) -> dict[str, Any]:
    """Exchange email + password for an access token and refresh token."""
    return await _post(
        settings,
        "/token",
        {"email": email, "password": password},
        params={"grant_type": "password"},
    )
