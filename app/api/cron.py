"""Daily WHOIS refresh — called by Vercel cron.

Vercel calls GET /cron/refresh-whois once per day and automatically injects:
    Authorization: Bearer {CRON_SECRET}

where CRON_SECRET is the environment variable set on the Vercel project.
We verify that secret before doing anything.

⚠ Vercel Hobby plan caps serverless functions at 10s.
  With more than a few domains you will hit that limit.
  Set maxDuration to 300 in vercel.json and upgrade to Pro.
"""

import asyncio
import hmac
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from app.config import Settings, get_settings
from app.cron_db import get_all_tracked_domains, upsert_whois_as_service
from app.whois_service import WhoisError, fetch_whois

log = logging.getLogger(__name__)

# Hidden from /docs — this is an internal endpoint, not part of the public API.
router = APIRouter(prefix="/cron", tags=["cron"], include_in_schema=False)


# ---------------------------------------------------------------------------
# Secret verification
# ---------------------------------------------------------------------------

def _verify_cron_secret(request: Request, settings: Settings) -> None:
    """Reject the request unless it carries the expected cron secret.

    Uses hmac.compare_digest so the check takes constant time regardless
    of how much of the secret the caller got right (timing-safe).
    """
    if not settings.cron_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CRON_SECRET is not configured on this server",
        )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing cron bearer token",
        )

    provided = auth_header.removeprefix("Bearer ")
    if not hmac.compare_digest(
        provided.encode("utf-8"),
        settings.cron_secret.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid cron secret",
        )


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

class CronRefreshResult(BaseModel):
    refreshed: int
    failed: int
    skipped: int          # domains with no change (future use)
    domains_ok: list[str]
    errors: dict[str, str]


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.get("/refresh-whois", response_model=CronRefreshResult)
async def refresh_whois_cron(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> CronRefreshResult:
    """Refresh WHOIS data for every domain tracked in the system.

    * Runs daily at 02:00 UTC (configured in vercel.json).
    * Processes domains sequentially with ``WHOIS_BATCH_DELAY`` seconds
      between each request to avoid hitting WHOIS server rate limits.
    * Uses the Supabase service-role key so it can read all users' domains.
    * Individual failures are logged and included in the response — one
      bad domain does not abort the entire run.
    """
    _verify_cron_secret(request, settings)

    if not settings.supabase_service_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SUPABASE_SERVICE_KEY is not configured — required for the cron job",
        )

    # ---- 1. Collect all distinct domains across all users ----
    try:
        domains = await get_all_tracked_domains(settings)
    except Exception as exc:
        log.error("Cron: failed to list domains — %s", exc)
        raise HTTPException(status_code=502, detail=f"Failed to list domains: {exc}") from exc

    log.info("Cron: starting WHOIS refresh for %d domain(s)", len(domains))

    if not domains:
        return CronRefreshResult(refreshed=0, failed=0, skipped=0, domains_ok=[], errors={})

    # ---- 2. Fetch WHOIS and upsert, one domain at a time ----
    domains_ok: list[str] = []
    errors: dict[str, str] = {}
    fetched_at = datetime.now(timezone.utc).isoformat()

    for i, domain in enumerate(domains):
        try:
            raw, parsed = await fetch_whois(domain, settings)
            await upsert_whois_as_service(settings, domain, raw, parsed, fetched_at)
            domains_ok.append(domain)
            log.info("Cron: ✓ %s  (%d/%d)", domain, i + 1, len(domains))
        except (WhoisError, Exception) as exc:
            errors[domain] = str(exc)
            log.warning("Cron: ✗ %s — %s", domain, exc)

        # Polite delay between lookups — skip after the last one.
        if i < len(domains) - 1 and settings.whois_batch_delay > 0:
            await asyncio.sleep(settings.whois_batch_delay)

    log.info(
        "Cron: done — %d refreshed, %d failed",
        len(domains_ok),
        len(errors),
    )
    return CronRefreshResult(
        refreshed=len(domains_ok),
        failed=len(errors),
        skipped=0,
        domains_ok=domains_ok,
        errors=errors,
    )
