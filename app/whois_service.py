"""Async WHOIS lookup using asyncwhois, with result serialisation.

asyncwhois returns datetime objects, lists, and other types that are not
directly JSON-serialisable.  We normalise them here before storing in JSONB.
"""

import asyncio
from datetime import date, datetime
from typing import Any

import asyncwhois

from app.config import Settings


class WhoisError(Exception):
    """WHOIS lookup failed. `status_code` maps to the HTTP response to return."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _serialize(value: Any) -> Any:
    """Recursively convert parser values to JSON-safe types."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize(item) for item in value if item is not None]
    return value


def serialize_parsed(parsed: dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-safe copy of asyncwhois's parser_output dict."""
    return {k: _serialize(v) for k, v in parsed.items() if v is not None}


async def fetch_whois(domain: str, settings: Settings) -> tuple[str, dict[str, Any]]:
    """Perform a live WHOIS lookup for *domain*.

    Returns ``(raw_text, parsed_dict)`` on success.
    Raises :class:`WhoisError` on timeout or lookup failure.

    We wrap the call in ``asyncio.wait_for`` because asyncwhois's own
    timeout handling varies across versions; this gives us a hard ceiling
    regardless.
    """
    try:
        query_output, parser_output = await asyncio.wait_for(
            asyncwhois.aio_whois(domain),
            timeout=settings.whois_timeout,
        )
    except asyncio.TimeoutError:
        raise WhoisError(504, f"WHOIS lookup for '{domain}' timed out after {settings.whois_timeout}s")
    except Exception as exc:
        raise WhoisError(502, f"WHOIS lookup failed: {exc}")

    raw: str = query_output or ""
    parsed: dict[str, Any] = serialize_parsed(parser_output or {})
    return raw, parsed
