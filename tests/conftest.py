"""Shared fixtures.

The auth tests mint their own ES256 tokens against a locally generated key so
they exercise claim validation without depending on Supabase's private key or
on network access.
"""

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

import app.security as security
from app.config import get_settings
from app.main import app

TEST_KID = "test-key-1"


@pytest.fixture(scope="session")
def settings():
    return get_settings()


@pytest.fixture(scope="session")
def keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": TEST_KID, "use": "sig", "alg": "ES256"})
    return {
        "private_pem": private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        "public_pem": private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        "key_set": jwt.PyJWKSet.from_dict({"keys": [jwk]}),
    }


@pytest.fixture(autouse=True)
def inject_jwks(keypair):
    """Pin the test key set as a fresh cache entry before every test.

    Without re-pinning per test, a case that triggers the rotation refetch
    replaces the cache with Supabase's real key set and silently invalidates
    every test after it.
    """
    security._jwks = keypair["key_set"]
    security._jwks_fetched_at = time.monotonic()
    yield
    security._jwks = None
    security._jwks_fetched_at = 0.0


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def base_claims(settings):
    now = int(time.time())
    return {
        "sub": "11111111-2222-3333-4444-555555555555",
        "aud": "authenticated",
        "iss": settings.jwt_issuer,
        "exp": now + 3600,
        "iat": now,
        "email": "user@example.com",
        "role": "authenticated",
    }


@pytest.fixture
def mint(keypair, base_claims):
    def _mint(headers=None, **overrides):
        claims = {k: v for k, v in {**base_claims, **overrides}.items() if v is not None}
        return jwt.encode(
            claims,
            keypair["private_pem"],
            algorithm="ES256",
            headers={"kid": TEST_KID, **(headers or {})},
        )

    return _mint
