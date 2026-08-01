"""Signup/login behaviour: rate limiting, secret redaction, and what the
responses are allowed to reveal. No network calls — GoTrue is stubbed."""

import pytest

import app.api.auth as auth_mod
from app.rate_limit import SlidingWindowLimiter
from app.supabase_client import SupabaseAuthError

PASSWORD = "Str0ng-Passw0rd-For-Testing"
EMAIL = "victim@example.com"

# Shapes captured from this project's live GoTrue responses.
UNCONFIRMED_USER = {
    "id": "daa8308a-dbcf-411d-abe9-cef40641586d",
    "email": EMAIL,
    "confirmed_at": None,
    "email_confirmed_at": None,
}
CONFIRMED_USER = dict(UNCONFIRMED_USER, confirmed_at="2026-08-01T12:00:00Z")


@pytest.fixture(autouse=True)
def fresh_limiters():
    """Give each test its own windows so ordering can't leak between them."""
    auth_mod._login_limiter = SlidingWindowLimiter(10, 300.0)
    auth_mod._signup_limiter = SlidingWindowLimiter(50, 3600.0)


@pytest.fixture
def stub_signup(monkeypatch):
    def _stub(payload):
        async def fake(*args, **kwargs):
            return payload

        monkeypatch.setattr(auth_mod, "sign_up", fake)

    return _stub


@pytest.fixture
def stub_login(monkeypatch):
    calls = {"n": 0}

    def _stub(payload=None, error=None):
        async def fake(*args, **kwargs):
            calls["n"] += 1
            if error:
                raise error
            return payload

        monkeypatch.setattr(auth_mod, "sign_in", fake)
        return calls

    return _stub


# --- signup ---------------------------------------------------------------


def test_signup_pending_confirmation_reveals_no_user_id(client, stub_signup):
    """Signing up with an already-registered address returns that account's real
    id from GoTrue. Relaying it would hand an unauthenticated caller the UUID
    that RLS policies and owner columns key on."""
    stub_signup(UNCONFIRMED_USER)
    response = client.post("/auth/signup", json={"email": EMAIL, "password": PASSWORD})

    assert response.status_code == 201
    assert response.json()["user_id"] is None
    assert UNCONFIRMED_USER["id"] not in response.text
    assert response.json()["confirmation_required"] is True


def test_signup_response_identical_for_new_and_existing_accounts(client, stub_signup):
    stub_signup(UNCONFIRMED_USER)
    first = client.post("/auth/signup", json={"email": EMAIL, "password": PASSWORD})
    stub_signup(dict(UNCONFIRMED_USER))  # GoTrue echoes the existing account
    second = client.post("/auth/signup", json={"email": EMAIL, "password": PASSWORD})

    assert first.text == second.text


def test_signup_returns_user_id_once_autoconfirmed(client, stub_signup):
    stub_signup(CONFIRMED_USER)
    response = client.post("/auth/signup", json={"email": EMAIL, "password": PASSWORD})

    assert response.json()["user_id"] == CONFIRMED_USER["id"]
    assert response.json()["confirmation_required"] is False


def test_signup_unwraps_nested_user_payload(client, stub_signup):
    stub_signup({"user": CONFIRMED_USER, "session": None})
    assert client.post("/auth/signup", json={"email": EMAIL, "password": PASSWORD}).json()["user_id"] == CONFIRMED_USER["id"]


# --- credential redaction -------------------------------------------------


def test_password_is_not_echoed_in_validation_errors(client):
    """FastAPI's default handler reflects the offending input, which would push
    plaintext passwords into access logs, proxies, and error trackers."""
    response = client.post("/auth/signup", json={"email": "a@b.com", "password": "hunter2"})

    assert response.status_code == 422
    assert "hunter2" not in response.text
    assert "at least 8" in response.text  # still actionable


def test_password_not_echoed_when_a_different_field_fails(client):
    response = client.post("/auth/signup", json={"email": "not-an-email", "password": PASSWORD})

    assert response.status_code == 422
    assert PASSWORD not in response.text
    assert "not-an-email" in response.text  # non-sensitive input is still useful


# --- rate limiting --------------------------------------------------------


def test_login_is_rate_limited_before_reaching_supabase(client, stub_login):
    auth_mod._login_limiter = SlidingWindowLimiter(2, 300.0)
    calls = stub_login(error=SupabaseAuthError(401, "Invalid login credentials"))

    body = {"email": EMAIL, "password": "wrong-password"}
    codes = [client.post("/auth/login", json=body).status_code for _ in range(5)]

    assert codes == [401, 401, 429, 429, 429]
    assert calls["n"] == 2, "blocked attempts must not reach the auth provider"


def test_rate_limited_response_carries_retry_after(client, stub_login):
    auth_mod._login_limiter = SlidingWindowLimiter(1, 300.0)
    stub_login(error=SupabaseAuthError(401, "Invalid login credentials"))

    body = {"email": EMAIL, "password": "wrong-password"}
    client.post("/auth/login", json=body)
    response = client.post("/auth/login", json=body)

    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 0


def test_successful_login_clears_the_window(client, stub_login):
    """Earlier typos must not count against a user who then logs in correctly."""
    auth_mod._login_limiter = SlidingWindowLimiter(3, 300.0)
    stub_login(error=SupabaseAuthError(401, "Invalid login credentials"))
    body = {"email": EMAIL, "password": "wrong-password"}
    client.post("/auth/login", json=body)
    client.post("/auth/login", json=body)

    stub_login(payload={
        "access_token": "tok", "refresh_token": "ref",
        "expires_in": 3600, "user": {"id": CONFIRMED_USER["id"], "email": EMAIL},
    })
    assert client.post("/auth/login", json={"email": EMAIL, "password": PASSWORD}).status_code == 200

    stub_login(error=SupabaseAuthError(401, "Invalid login credentials"))
    assert client.post("/auth/login", json=body).status_code == 401


def test_limiter_isolates_accounts_and_source_ips():
    limiter = SlidingWindowLimiter(2, 60.0)
    limiter.hit("1.2.3.4|victim@x.com")
    limiter.hit("1.2.3.4|victim@x.com")

    assert limiter.hit("1.2.3.4|victim@x.com") is not None
    # An attacker must not be able to lock a victim out of their own account...
    assert limiter.hit("9.9.9.9|victim@x.com") is None
    # ...nor should one account's failures throttle another.
    assert limiter.hit("1.2.3.4|other@x.com") is None


def test_upstream_5xx_is_not_relayed_to_the_client(client, stub_login):
    """A 5xx body from GoTrue can carry upstream internals."""
    stub_login(error=SupabaseAuthError(502, "Authentication service error"))
    response = client.post("/auth/login", json={"email": EMAIL, "password": PASSWORD})

    assert response.status_code == 502
    assert response.json()["detail"] == "Authentication service error"
