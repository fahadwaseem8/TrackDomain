from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app.config import Settings, get_settings
from app.security import CurrentUser, get_current_user
from app.supabase_client import SupabaseAuthError, sign_in, sign_up

router = APIRouter(prefix="/auth", tags=["auth"])


class Credentials(BaseModel):
    email: EmailStr
    # Supabase enforces its own minimum; 8 is a floor we apply before the round trip.
    password: str = Field(min_length=8, max_length=72)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    email: str | None = None


class SignupResponse(BaseModel):
    user_id: str
    email: str | None = None
    confirmation_required: bool
    message: str


def _token_response(payload: dict[str, Any]) -> TokenResponse:
    user = payload.get("user") or {}
    return TokenResponse(
        access_token=payload["access_token"],
        refresh_token=payload["refresh_token"],
        token_type=payload.get("token_type", "bearer"),
        expires_in=payload.get("expires_in", 3600),
        user_id=user.get("id", ""),
        email=user.get("email"),
    )


@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new account",
)
async def signup(
    credentials: Credentials,
    settings: Settings = Depends(get_settings),
) -> SignupResponse:
    """Create an account. The project requires email confirmation, so no token
    is issued here — the user must confirm before they can log in."""
    try:
        payload = await sign_up(settings, credentials.email, credentials.password)
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    # With confirmation on, GoTrue returns the user at the top level and no session.
    user = payload.get("user") or payload
    confirmed = bool(user.get("confirmed_at") or user.get("email_confirmed_at"))

    return SignupResponse(
        user_id=user.get("id", ""),
        email=user.get("email"),
        confirmation_required=not confirmed,
        message=(
            "Account created. Check your email to confirm it before logging in."
            if not confirmed
            else "Account created. You can now log in."
        ),
    )


@router.post("/login", response_model=TokenResponse, summary="Exchange credentials for a token")
async def login(
    credentials: Credentials,
    settings: Settings = Depends(get_settings),
) -> TokenResponse:
    """Log in and receive a Supabase-issued JWT access token."""
    try:
        payload = await sign_in(settings, credentials.email, credentials.password)
    except SupabaseAuthError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
            headers={"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None,
        ) from exc

    return _token_response(payload)


@router.get("/me", response_model=CurrentUser, summary="Current authenticated user")
async def me(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
    """Return the caller identified by the bearer token — the protected-route pattern."""
    return user
