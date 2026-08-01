"""Domain tracking list endpoints.

Routes
------
GET    /domains           List the authenticated user's tracked domains
POST   /domains           Add a domain to the tracking list
DELETE /domains/{id}      Remove a domain from the tracking list
"""

import uuid

import tldextract
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator

from app.config import Settings, get_settings
from app.domains_db import DomainDBError, add_domain, list_domains, remove_domain
from app.security import CurrentUser, bearer_scheme, get_current_user

router = APIRouter(prefix="/domains", tags=["domains"])


# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------

def _strip_scheme(raw: str) -> str:
    """Remove leading https:// / http:// and any trailing path."""
    raw = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    return raw.split("/")[0].split("?")[0].split("#")[0]


def _validate_and_normalize(raw: str) -> str:
    """Return the bare hostname, or raise ValueError if it's not a valid domain."""
    clean = _strip_scheme(raw)
    ext = tldextract.extract(clean)
    if not ext.domain or not ext.suffix:
        raise ValueError(f"'{clean}' is not a valid domain name")
    # Reconstruct the full hostname (preserving subdomains, e.g. blog.example.com)
    parts = [p for p in (ext.subdomain, ext.domain, ext.suffix) if p]
    return ".".join(parts)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class AddDomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        try:
            return _validate_and_normalize(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class DomainResponse(BaseModel):
    id: str
    domain: str
    created_at: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=list[DomainResponse],
    summary="List tracked domains",
)
async def get_domains(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    user: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> list[DomainResponse]:
    """Return all domains the authenticated user is tracking, newest first."""
    try:
        rows = await list_domains(settings, credentials.credentials)
    except DomainDBError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return [DomainResponse(**row) for row in rows]


@router.post(
    "",
    response_model=DomainResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add a domain to the tracking list",
)
async def add_domain_route(
    body: AddDomainRequest,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    user: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> DomainResponse:
    """Add a domain to the tracking list.

    The domain is normalised (scheme stripped, lowercased) before saving.
    Adding the same domain twice returns **409 Conflict**.
    """
    try:
        row = await add_domain(settings, credentials.credentials, body.domain, user.id)
    except DomainDBError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    return DomainResponse(**row)


@router.delete(
    "/{domain_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a domain from the tracking list",
)
async def delete_domain_route(
    domain_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    user: CurrentUser = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
) -> None:
    """Remove a tracked domain by its id.

    Returns **404** if the domain doesn't exist or doesn't belong to the caller
    (RLS makes both cases indistinguishable, which is intentional).
    """
    # Validate uuid format early so we don't hit the DB with garbage
    try:
        uuid.UUID(domain_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="domain_id must be a valid UUID",
        )

    try:
        found = await remove_domain(settings, credentials.credentials, domain_id)
    except DomainDBError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
