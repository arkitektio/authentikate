"""Revocation-list checking: a verified token is refused while its ``jti`` is on
the issuer's list, and the list is fetched at most once per refresh interval
however many tokens are checked in between.
"""

import asyncio
import datetime
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from authentikate import revocation
from authentikate.base_models import AuthentikateSettings
from authentikate.decode import adecode_token, decode_token
from authentikate.errors import MalformedJwtTokenError, TokenRevokedError
from authentikate.revocation import RevocationList

ISS = "https://lok.example"
REVOCATION_URI = "https://lok.example/o/revoked/"


def _settings(public_key: str, **issuer_extra: Any) -> AuthentikateSettings:
    return AuthentikateSettings(
        issuers=[{"kind": "rsa", "iss": ISS, "public_key": public_key, **issuer_extra}],
        audience="*",
    )


def _token(private_key: str, jti: str | None = "jti-1") -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    claims: dict[str, object] = {
        "sub": "1",
        "iss": ISS,
        "aud": "mikro",
        "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "client_id": "client",
        "preferred_username": "user",
        "roles": ["user"],
        "scope": "openid",
    }
    if jti is not None:
        claims["jti"] = jti

    return jwt.encode({"alg": "RS256", "kid": "1"}, claims, RSAKey.import_key(private_key))


class _FakeClient:
    """Stands in for ``httpx.AsyncClient``: serves canned payloads and counts requests."""

    def __init__(self, *payloads: Any, fail: bool = False) -> None:
        self.payloads = list(payloads)
        self.fail = fail
        self.calls: list[str] = []

    def __call__(self, *args: Any, **kwargs: Any) -> "_FakeClient":
        return self

    async def __aenter__(self) -> "_FakeClient":
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    async def get(self, url: str) -> MagicMock:
        self.calls.append(url)
        if self.fail:
            raise ConnectionError("issuer unreachable")
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = self.payloads.pop(0) if len(self.payloads) > 1 else self.payloads[0]
        return response


def _patch_client(client: _FakeClient) -> Any:
    return patch.object(revocation.httpx, "AsyncClient", client)


# --- decode path ----------------------------------------------------------


@pytest.mark.asyncio
async def test_revoked_token_is_refused_and_live_token_accepted(key_pair_str) -> None:
    settings = _settings(key_pair_str.public_key, revocation_uri=REVOCATION_URI)
    client = _FakeClient({"revoked": ["jti-revoked"]})

    with _patch_client(client):
        assert (await adecode_token(_token(key_pair_str.private_key, "jti-live"), settings)).jti == "jti-live"

        with pytest.raises(TokenRevokedError) as excinfo:
            await adecode_token(_token(key_pair_str.private_key, "jti-revoked"), settings)

    assert excinfo.value.reason == "TOKEN_REVOKED"
    assert excinfo.value.code == "UNAUTHENTICATED"
    assert client.calls == [REVOCATION_URI]


def test_sync_decode_path_checks_revocation(key_pair_str) -> None:
    settings = _settings(key_pair_str.public_key, revocation_uri=REVOCATION_URI)

    with _patch_client(_FakeClient(["jti-revoked"])):
        assert decode_token(_token(key_pair_str.private_key, "jti-live"), settings).jti == "jti-live"
        with pytest.raises(TokenRevokedError):
            decode_token(_token(key_pair_str.private_key, "jti-revoked"), settings)


@pytest.mark.asyncio
async def test_token_without_jti_is_refused_when_revocation_is_configured(key_pair_str) -> None:
    settings = _settings(key_pair_str.public_key, revocation_uri=REVOCATION_URI)

    with _patch_client(_FakeClient({"revoked": []})):
        with pytest.raises(MalformedJwtTokenError):
            await adecode_token(_token(key_pair_str.private_key, jti=None), settings)


@pytest.mark.asyncio
async def test_unconfigured_issuer_never_fetches_and_accepts_tokens_without_jti(key_pair_str) -> None:
    settings = _settings(key_pair_str.public_key)
    client = _FakeClient({"revoked": ["jti-1"]})

    with _patch_client(client):
        # Even a jti that *would* be on the list is accepted: nothing is consulted.
        assert (await adecode_token(_token(key_pair_str.private_key, "jti-1"), settings)).jti == "jti-1"
        assert (await adecode_token(_token(key_pair_str.private_key, jti=None), settings)).jti is None

    assert client.calls == []


@pytest.mark.asyncio
async def test_revocation_is_checked_only_after_the_signature(key_pair_str, private_key) -> None:
    """A forged token must not be able to trigger a fetch or a revocation error."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()

    settings = _settings(key_pair_str.public_key, revocation_uri=REVOCATION_URI)
    client = _FakeClient({"revoked": ["jti-revoked"]})

    with _patch_client(client):
        with pytest.raises(Exception) as excinfo:
            await adecode_token(_token(other_pem, "jti-revoked"), settings)

    assert not isinstance(excinfo.value, TokenRevokedError)
    assert client.calls == []


# --- fetch budget ---------------------------------------------------------


@pytest.mark.asyncio
async def test_many_checks_within_the_interval_cost_one_fetch(key_pair_str) -> None:
    settings = _settings(key_pair_str.public_key, revocation_uri=REVOCATION_URI, revocation_refresh_interval=60.0)
    client = _FakeClient({"revoked": []})

    with _patch_client(client):
        for i in range(50):
            await adecode_token(_token(key_pair_str.private_key, f"jti-{i}"), settings)

    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_concurrent_checks_share_one_fetch() -> None:
    revoked = RevocationList(REVOCATION_URI, refresh_interval=60.0, request_timeout=5.0)
    client = _FakeClient({"revoked": ["x"]})

    with _patch_client(client):
        results = await asyncio.gather(*(revoked.ais_revoked("x") for _ in range(20)))

    assert all(results)
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_list_is_refetched_once_the_interval_has_elapsed() -> None:
    revoked = RevocationList(REVOCATION_URI, refresh_interval=60.0, request_timeout=5.0)
    client = _FakeClient({"revoked": []}, {"revoked": ["late"]})
    clock = {"now": 1000.0}

    with _patch_client(client), patch.object(revocation.time, "monotonic", lambda: clock["now"]):
        assert await revoked.ais_revoked("late") is False
        clock["now"] += 59.0
        assert await revoked.ais_revoked("late") is False  # still cached
        clock["now"] += 1.0
        assert await revoked.ais_revoked("late") is True  # refreshed

    assert len(client.calls) == 2


def test_interval_is_configurable_with_uppercase_aliases(key_pair_str) -> None:
    settings = AuthentikateSettings(
        ISSUERS=[
            {
                "kind": "rsa",
                "iss": ISS,
                "public_key": key_pair_str.public_key,
                "REVOCATION_URI": REVOCATION_URI,
                "REVOCATION_REFRESH_INTERVAL": 300,
                "REVOCATION_REQUEST_TIMEOUT": 2,
            }
        ],
        AUDIENCE="*",
    )
    issuer = settings.issuers[0]
    assert issuer.revocation_uri == REVOCATION_URI
    assert issuer.revocation_refresh_interval == 300.0
    assert issuer.revocation_request_timeout == 2.0


# --- failure handling -----------------------------------------------------


@pytest.mark.asyncio
async def test_failed_refresh_keeps_the_stale_list_and_waits_for_the_interval(caplog) -> None:
    revoked = RevocationList(REVOCATION_URI, refresh_interval=60.0, request_timeout=5.0)
    client = _FakeClient({"revoked": ["stale"]})
    clock = {"now": 0.0}

    with _patch_client(client), patch.object(revocation.time, "monotonic", lambda: clock["now"]):
        assert await revoked.ais_revoked("stale") is True

        client.fail = True
        clock["now"] += 60.0
        with caplog.at_level(logging.WARNING, logger="authentikate.revocation"):
            assert await revoked.ais_revoked("stale") is True  # stale copy still answers
            assert await revoked.ais_revoked("stale") is True  # and no retry before the interval

    assert len(client.calls) == 2
    assert any("keeping the copy" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_unreachable_list_fails_open_until_it_loads(key_pair_str, caplog) -> None:
    settings = _settings(key_pair_str.public_key, revocation_uri=REVOCATION_URI)
    client = _FakeClient({"revoked": ["jti-1"]}, fail=True)

    with _patch_client(client), caplog.at_level(logging.WARNING, logger="authentikate.revocation"):
        token = await adecode_token(_token(key_pair_str.private_key, "jti-1"), settings)

    assert token.jti == "jti-1"
    assert any("no token is treated as revoked" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_malformed_list_is_treated_as_a_failed_fetch() -> None:
    revoked = RevocationList(REVOCATION_URI, refresh_interval=60.0, request_timeout=5.0)

    with _patch_client(_FakeClient({"revoked": "not-a-list"})):
        assert await revoked.ais_revoked("x") is False

    assert revoked.revoked == frozenset()


def test_sync_check_inside_a_running_loop_is_a_programming_error() -> None:
    revoked = RevocationList(REVOCATION_URI, refresh_interval=60.0, request_timeout=5.0)

    async def inside_loop() -> None:
        with pytest.raises(RuntimeError):
            revoked.is_revoked("x")

    asyncio.run(inside_loop())


def test_exported_from_the_package() -> None:
    import authentikate

    assert authentikate.TokenRevokedError is TokenRevokedError
