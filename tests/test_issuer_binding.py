"""Regression tests for cross-issuer token forgery.

Before the fix, every configured issuer's JWKS was merged into one flat KeySet
indexed by ``kid``, and the ``iss`` claim was never checked against the issuer
that owned the resolved key. Any configured issuer could therefore mint a token
claiming a *different* issuer and impersonate that issuer's users -- with
arbitrary roles and organization -- since users are keyed on ``(sub, iss)``.
"""

import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from joserfc import jwt
from joserfc.jwk import RSAKey

from authentikate.base_models import AuthentikateSettings
from authentikate.decode import adecode_token, decode_token
from authentikate.errors import InvalidJwtTokenError, MalformedJwtTokenError

ISS_A = "https://idp-a.example"
ISS_B = "https://idp-b.example"


def _keypair() -> tuple[RSAKey, str]:
    """Make an RSA keypair as (signing key, PEM public key)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return RSAKey.import_key(private_pem), public_pem.decode()


def _claims(iss: str, **overrides: object) -> dict[str, object]:
    now = datetime.datetime.now(datetime.timezone.utc)
    claims: dict[str, object] = {
        "sub": "victim",
        "iss": iss,
        "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "client_id": "client",
        "preferred_username": "victim",
        "roles": ["admin"],
        "scope": "openid",
        "aud": ["test-service"],
        "org": "acme",
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def two_issuers() -> tuple[AuthentikateSettings, RSAKey, RSAKey]:
    """Two RSA issuers, each with its own keypair, both on the default key_id."""
    key_a, pub_a = _keypair()
    key_b, pub_b = _keypair()

    settings = AuthentikateSettings(
        audience="*",
        issuers=[
            {"kind": "rsa", "iss": ISS_A, "public_key": pub_a},
            {"kind": "rsa", "iss": ISS_B, "public_key": pub_b},
        ]
    )
    return settings, key_a, key_b


def test_issuer_cannot_mint_a_token_for_another_issuer(two_issuers) -> None:
    """Issuer A signing a token that claims `iss: B` must be rejected."""
    settings, key_a, _ = two_issuers

    forged = jwt.encode(
        {"alg": "RS256", "kid": "1"}, _claims(ISS_B), key_a
    )

    with pytest.raises(InvalidJwtTokenError):
        decode_token(forged, settings)


@pytest.mark.asyncio
async def test_issuer_cannot_mint_a_token_for_another_issuer_async(
    two_issuers,
) -> None:
    """The async path must bind `iss` to the signing key just as the sync one does."""
    settings, key_a, _ = two_issuers

    forged = jwt.encode({"alg": "RS256", "kid": "1"}, _claims(ISS_B), key_a)

    with pytest.raises(InvalidJwtTokenError):
        await adecode_token(forged, settings)


def test_each_issuer_still_authenticates_its_own_users(two_issuers) -> None:
    """The fix must not break legitimate multi-issuer operation.

    Both issuers here use the default ``key_id`` of "1". Before the fix that
    alone raised `JwksError: Duplicate kid found: 1` on *every* authentication,
    because keys were merged across issuers.
    """
    settings, key_a, key_b = two_issuers

    token_a = jwt.encode({"alg": "RS256", "kid": "1"}, _claims(ISS_A), key_a)
    token_b = jwt.encode({"alg": "RS256", "kid": "1"}, _claims(ISS_B), key_b)

    assert decode_token(token_a, settings).iss == ISS_A
    assert decode_token(token_b, settings).iss == ISS_B


def test_unconfigured_issuer_is_rejected(two_issuers) -> None:
    """A token naming an unknown issuer is rejected outright."""
    settings, key_a, _ = two_issuers

    token = jwt.encode(
        {"alg": "RS256", "kid": "1"}, _claims("https://evil.example"), key_a
    )

    with pytest.raises(InvalidJwtTokenError, match="Untrusted issuer"):
        decode_token(token, settings)


def test_token_without_iss_is_rejected(two_issuers) -> None:
    """A token with no `iss` claim cannot select a trust anchor."""
    settings, key_a, _ = two_issuers

    claims = _claims(ISS_A)
    del claims["iss"]
    token = jwt.encode({"alg": "RS256", "kid": "1"}, claims, key_a)

    with pytest.raises(MalformedJwtTokenError, match="Missing iss"):
        decode_token(token, settings)


@pytest.mark.asyncio
async def test_unconfigured_issuer_triggers_no_jwks_fetch() -> None:
    """An untrusted issuer must be rejected before any outbound JWKS request.

    Otherwise an unauthenticated attacker could drive one live fetch per
    request just by naming an unknown issuer.
    """
    key, _ = _keypair()

    session = AsyncMock()
    session.__aenter__.return_value = session
    session.__aexit__.return_value = False
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"keys": []}
    session.get.return_value = response

    with patch("authentikate.base_models.httpx.AsyncClient", return_value=session):
        settings = AuthentikateSettings(
            audience="*",
            issuers=[
                {
                    "kind": "jwks_uri",
                    "iss": ISS_A,
                    "jwks_uri": "http://idp-a.example/jwks",
                }
            ]
        )
        token = jwt.encode(
            {"alg": "RS256", "kid": "1"}, _claims("https://evil.example"), key
        )

        with pytest.raises(InvalidJwtTokenError, match="Untrusted issuer"):
            await adecode_token(token, settings)

    assert session.get.call_count == 0
