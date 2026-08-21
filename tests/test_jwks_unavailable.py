"""An unreachable JWKS endpoint must not turn inbound requests into outbound ones.

Refreshes were already throttled, but the *initial* load was not -- and the
initial load is exactly what runs when the issuer has been unreachable since the
process started. Each attempt held the cache lock for the whole request timeout,
so concurrent requests queued behind one another: an unauthenticated caller could
stall authentication for everyone while hammering the struggling issuer.
"""

import asyncio

import httpx
import pytest

from authentikate.base_models import JWKSUriIssuer
from authentikate.errors import JwksError


class _CountingFailingTransport(httpx.AsyncBaseTransport):
    """Stands in for an issuer that accepts the connection and then hangs."""

    def __init__(self, delay: float = 0.05) -> None:
        self.calls = 0
        self.delay = delay

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        await asyncio.sleep(self.delay)
        raise httpx.ConnectError("issuer unreachable", request=request)


@pytest.fixture
def failing_issuer(monkeypatch):
    transport = _CountingFailingTransport()
    # Bind the real class first: the patched name would otherwise resolve back
    # to this lambda when it is called.
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "authentikate.base_models.httpx.AsyncClient",
        lambda *a, **kw: real_client(transport=transport),
    )
    issuer = JWKSUriIssuer(
        iss="https://idp.example",
        jwks_uri="https://idp.example/.well-known/jwks.json",
    )
    return issuer, transport


def test_a_dead_issuer_is_contacted_once_per_interval(failing_issuer) -> None:
    issuer, transport = failing_issuer

    async def scenario() -> None:
        async def one() -> None:
            with pytest.raises(JwksError):
                await issuer.aget_as_jwks()

        await asyncio.gather(*[one() for _ in range(20)])

    asyncio.run(scenario())

    assert transport.calls == 1, (
        "every inbound request drove its own outbound JWKS fetch: "
        f"{transport.calls} fetches for 20 requests"
    )


def test_the_cooldown_expires_so_the_issuer_can_recover(failing_issuer) -> None:
    issuer, transport = failing_issuer
    # A short interval keeps the test fast; the production default is 10s.
    issuer.min_refresh_interval = 0.0

    async def scenario() -> None:
        for _ in range(3):
            with pytest.raises(JwksError):
                await issuer.aget_as_jwks()

    asyncio.run(scenario())

    assert transport.calls == 3


def test_a_successful_load_clears_the_failure(monkeypatch) -> None:
    """Once the issuer answers, the cooldown must not linger and block it."""
    from joserfc.jwk import OKPKey

    key = OKPKey.generate_key("Ed25519").as_dict(private=False, kid="k1")
    state = {"up": False, "calls": 0}

    class _Flaky(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            state["calls"] += 1
            if not state["up"]:
                raise httpx.ConnectError("down", request=request)
            return httpx.Response(200, json={"keys": [key]})

    transport = _Flaky()
    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "authentikate.base_models.httpx.AsyncClient",
        lambda *a, **kw: real_client(transport=transport),
    )
    issuer = JWKSUriIssuer(
        iss="https://idp.example",
        jwks_uri="https://idp.example/jwks",
        min_refresh_interval=0.0,
    )

    async def scenario() -> None:
        with pytest.raises(JwksError):
            await issuer.aget_as_jwks()

        state["up"] = True
        assert len(await issuer.aget_as_jwks()) == 1
        # Now cached: no further outbound request.
        assert len(await issuer.aget_as_jwks()) == 1

    asyncio.run(scenario())
    assert state["calls"] == 2


def test_the_request_timeout_is_stated_explicitly() -> None:
    """The bound on an auth-path network call must not be a dependency default."""
    issuer = JWKSUriIssuer(iss="https://idp.example", jwks_uri="https://idp.example/jwks")
    assert issuer.request_timeout == 5.0

    configured = JWKSUriIssuer(
        iss="https://idp.example",
        jwks_uri="https://idp.example/jwks",
        request_timeout=1.5,
    )
    assert configured.request_timeout == 1.5
