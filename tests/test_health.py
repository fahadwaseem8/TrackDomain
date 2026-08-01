"""Health endpoint status mapping. Supabase is stubbed — no network calls."""

import httpx
import pytest

import app.db as db_mod
from app.config import Settings, get_settings
from app.main import app


@pytest.fixture
def override_settings():
    def _override(**changes):
        cfg = get_settings().model_copy(update=changes)
        app.dependency_overrides[get_settings] = lambda: cfg
        return cfg

    yield _override
    app.dependency_overrides.clear()


@pytest.fixture
def stub_transport(monkeypatch):
    """Swap httpx's network layer for a scripted responder."""

    def _stub(handler):
        class FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url, **kwargs):
                return handler(url)

        monkeypatch.setattr(db_mod.httpx, "AsyncClient", FakeClient)

    return _stub


def ok(url):
    return httpx.Response(200, json={"name": "GoTrue"}, request=httpx.Request("GET", url))


def test_healthy_reports_200(client, stub_transport):
    stub_transport(ok)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["database"]["status"] == "ok"


def test_unconfigured_supabase_is_degraded(client, override_settings):
    override_settings(supabase_url="", supabase_key="")
    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["database"]["status"] == "not_configured"


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [(401, "unauthorized"), (403, "unauthorized"), (500, "error")],
)
def test_error_statuses_are_classified(client, stub_transport, status_code, expected):
    stub_transport(lambda url: httpx.Response(status_code, request=httpx.Request("GET", url)))
    response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["database"]["status"] == expected


def test_timeout_is_reported(client, stub_transport):
    def raise_timeout(url):
        raise httpx.TimeoutException("too slow")

    stub_transport(raise_timeout)
    assert client.get("/health").json()["database"]["status"] == "timeout"


def test_unreachable_host_is_reported(client, stub_transport):
    def raise_connect(url):
        raise httpx.ConnectError("dns failure")

    stub_transport(raise_connect)
    assert client.get("/health").json()["database"]["status"] == "unreachable"


def test_missing_health_table_is_reported(client, stub_transport, override_settings):
    override_settings(supabase_health_table="no_such_table")
    stub_transport(
        lambda url: ok(url)
        if "/auth/v1/health" in url
        else httpx.Response(404, request=httpx.Request("GET", url))
    )
    response = client.get("/health")

    assert response.status_code == 503
    assert "no_such_table" in response.json()["database"]["detail"]
