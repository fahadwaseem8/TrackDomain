"""Token validation on protected routes.

Each case asserts the *reason* for rejection, not just the status — a 401 for
the wrong reason means the defense under test never ran.
"""

import base64
import hashlib
import hmac
import json

import jwt
import pytest

from tests.conftest import TEST_KID


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _b64(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def forge_hs256(claims: dict, secret: bytes) -> str:
    """Hand-rolled HS256 token. PyJWT refuses to sign a token whose key is an
    asymmetric public key, so the algorithm-confusion attack has to be built by
    hand — as an attacker would."""
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": TEST_KID}).encode())
    payload = _b64(json.dumps(claims).encode())
    signature = _b64(hmac.new(secret, header + b"." + payload, hashlib.sha256).digest())
    return (header + b"." + payload + b"." + signature).decode()


def test_valid_token_is_accepted(client, mint, base_claims):
    response = client.get("/auth/me", headers=auth(mint()))
    assert response.status_code == 200
    assert response.json() == {
        "id": base_claims["sub"],
        "email": base_claims["email"],
        "role": "authenticated",
    }


def test_missing_token_is_rejected(client):
    assert client.get("/auth/me").status_code == 401


@pytest.mark.parametrize("token", ["notatoken", "", "a.b.c"])
def test_malformed_tokens_are_rejected(client, token):
    assert client.get("/auth/me", headers=auth(token)).status_code == 401


def test_tampered_payload_fails_signature_check(client, mint):
    response = client.get("/auth/me", headers=auth(mint()[:-4] + "AAAA"))
    assert response.status_code == 401
    assert "signature" in response.json()["detail"].lower()


def test_alg_none_is_rejected(client, base_claims):
    token = jwt.encode(base_claims, key=None, algorithm="none", headers={"kid": TEST_KID})
    response = client.get("/auth/me", headers=auth(token))
    assert response.status_code == 401
    assert "not allowed" in response.json()["detail"]


def test_algorithm_confusion_with_public_key_is_rejected(client, keypair, base_claims):
    """The classic downgrade: sign HS256 using the ES256 public key as the HMAC
    secret. Verification must pin the algorithm from the JWKS, not the header."""
    token = forge_hs256(base_claims, keypair["public_pem"])
    response = client.get("/auth/me", headers=auth(token))
    assert response.status_code == 401
    assert "not allowed" in response.json()["detail"]


def test_expired_token_is_rejected(client, mint, base_claims):
    response = client.get("/auth/me", headers=auth(mint(exp=base_claims["iat"] - 10)))
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_wrong_audience_is_rejected(client, mint):
    response = client.get("/auth/me", headers=auth(mint(aud="anon")))
    assert response.status_code == 401
    assert "audience" in response.json()["detail"].lower()


def test_wrong_issuer_is_rejected(client, mint):
    response = client.get("/auth/me", headers=auth(mint(iss="https://evil.example.com/auth/v1")))
    assert response.status_code == 401
    assert "issuer" in response.json()["detail"].lower()


@pytest.mark.parametrize("claim", ["sub", "exp"])
def test_required_claims_are_enforced(client, mint, claim):
    response = client.get("/auth/me", headers=auth(mint(**{claim: None})))
    assert response.status_code == 401
    assert claim in response.json()["detail"]


def test_anonymous_sessions_are_rejected(client, mint):
    """Supabase anonymous sign-ins also carry role 'authenticated'; enabling
    them in the dashboard must not silently admit drive-by visitors."""
    response = client.get("/auth/me", headers=auth(mint(is_anonymous=True)))
    assert response.status_code == 401
    assert "anonymous" in response.json()["detail"].lower()


def test_unknown_kid_is_rejected(client, mint):
    response = client.get("/auth/me", headers=auth(mint(headers={"kid": "nope"})))
    assert response.status_code == 401
    assert "unknown key" in response.json()["detail"].lower()


def test_missing_kid_is_rejected(client, keypair, base_claims):
    token = jwt.encode(base_claims, keypair["private_pem"], algorithm="ES256")
    response = client.get("/auth/me", headers=auth(token))
    assert response.status_code == 401
    assert "key id" in response.json()["detail"].lower()


def test_unknown_kid_does_not_trigger_unbounded_refetches(client, mint, monkeypatch):
    """An unknown `kid` is attacker-controlled. Refetching on every miss would
    let anyone turn cheap requests into outbound traffic against Supabase."""
    import app.security as security

    calls = {"n": 0}
    original = security._fetch_jwks

    async def counting_fetch(settings):
        calls["n"] += 1
        return await original(settings)

    monkeypatch.setattr(security, "_fetch_jwks", counting_fetch)
    for _ in range(25):
        client.get("/auth/me", headers=auth(mint(headers={"kid": "random-kid"})))

    assert calls["n"] <= 1, f"{calls['n']} outbound JWKS fetches from 25 forged requests"
