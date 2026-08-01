"""Verification of Supabase-issued JWTs.

Supabase signs access tokens with an asymmetric key (ES256) and publishes the
public half at `/auth/v1/.well-known/jwks.json`, so tokens are verified locally
here — no shared secret, and no network round trip per request once the key set
is cached.
"""

import time

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKSet
from pydantic import BaseModel

from app.config import Settings, get_settings

bearer_scheme = HTTPBearer(description="Supabase access token")

_jwks: PyJWKSet | None = None
_jwks_fetched_at: float = 0.0


class CurrentUser(BaseModel):
    """The authenticated caller, as described by their access token."""

    id: str
    email: str | None = None
    role: str | None = None


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _fetch_jwks(settings: Settings) -> PyJWKSet:
    global _jwks, _jwks_fetched_at
    try:
        async with httpx.AsyncClient(timeout=settings.health_check_timeout) as client:
            response = await client.get(
                f"{settings.auth_url}/.well-known/jwks.json",
                headers={"apikey": settings.supabase_key},
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Could not fetch signing keys: {exc}",
        ) from exc

    _jwks = PyJWKSet.from_dict(response.json())
    _jwks_fetched_at = time.monotonic()
    return _jwks


async def _signing_key(settings: Settings, kid: str) -> jwt.PyJWK:
    """Resolve a key id to its public key, refetching once on a cache miss
    so that key rotation doesn't require a restart."""
    stale = _jwks is None or time.monotonic() - _jwks_fetched_at > settings.jwks_cache_ttl
    key_set = await _fetch_jwks(settings) if stale else _jwks

    try:
        return key_set[kid]
    except KeyError:
        pass

    if stale:  # already the newest key set — the kid genuinely isn't ours
        raise _unauthorized("Token signed with an unknown key")

    try:
        return (await _fetch_jwks(settings))[kid]
    except KeyError:
        raise _unauthorized("Token signed with an unknown key") from None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    """Validate the bearer token and return the caller it identifies."""
    token = credentials.credentials

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise _unauthorized("Malformed token") from None

    kid = header.get("kid")
    if not kid:
        raise _unauthorized("Token is missing a key id")

    key = await _signing_key(settings, kid)

    try:
        claims = jwt.decode(
            token,
            key=key.key,
            # Pin to the algorithm declared by the JWKS, never the one in the
            # token header — trusting the header is the algorithm-confusion hole
            # that lets an attacker downgrade ES256 to HS256 and sign with the
            # public key as the HMAC secret.
            algorithms=[key.algorithm_name],
            audience="authenticated",
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token has expired") from None
    except jwt.InvalidTokenError as exc:
        raise _unauthorized(f"Invalid token: {exc}") from None

    return CurrentUser(
        id=claims["sub"],
        email=claims.get("email"),
        role=claims.get("role"),
    )
