"""Regression tests for auth-token audience validation.

Before the fix `_validate_claims` only required `exp`, and `AuthentikateSettings`
had no `audience` field at all -- so a token an issuer minted for service X was
accepted verbatim by service Y.
"""

import datetime

import pytest
from pydantic import ValidationError
from joserfc import jwt
from joserfc.jwk import RSAKey

from authentikate.base_models import AuthentikateSettings
from authentikate.decode import decode_token
from authentikate.errors import InvalidJwtTokenError

ISS = "https://idp.example"


def _settings(public_key: str, audience: str | None) -> AuthentikateSettings:
    return AuthentikateSettings(
        issuers=[{"kind": "rsa", "iss": ISS, "public_key": public_key}],
        audience=audience,
    )


def _token(private_key: str, aud: object) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    claims: dict[str, object] = {
        "sub": "1",
        "iss": ISS,
        "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "client_id": "client",
        "preferred_username": "user",
        "roles": ["user"],
        "scope": "openid",
    }
    if aud is not None:
        claims["aud"] = aud

    return jwt.encode(
        {"alg": "RS256", "kid": "1"}, claims, RSAKey.import_key(private_key)
    )


def test_token_for_another_service_is_rejected(key_pair_str) -> None:
    settings = _settings(key_pair_str.public_key, audience="mikro")
    token = _token(key_pair_str.private_key, ["fluss"])

    with pytest.raises(InvalidJwtTokenError):
        decode_token(token, settings)


def test_token_for_this_service_is_accepted(key_pair_str) -> None:
    settings = _settings(key_pair_str.public_key, audience="mikro")
    token = _token(key_pair_str.private_key, ["mikro"])

    assert decode_token(token, settings).aud == ["mikro"]


def test_list_valued_aud_matches_on_membership(key_pair_str) -> None:
    """A token scoped to several services is valid at each of them."""
    settings = _settings(key_pair_str.public_key, audience="mikro")
    token = _token(key_pair_str.private_key, ["fluss", "mikro"])

    assert decode_token(token, settings).aud == ["fluss", "mikro"]


def test_scalar_aud_is_accepted(key_pair_str) -> None:
    settings = _settings(key_pair_str.public_key, audience="mikro")
    token = _token(key_pair_str.private_key, "mikro")

    assert decode_token(token, settings).aud == ["mikro"]


def test_missing_aud_is_rejected_when_audience_configured(key_pair_str) -> None:
    """Configuring an audience makes the claim essential, not merely checked."""
    settings = _settings(key_pair_str.public_key, audience="mikro")
    token = _token(key_pair_str.private_key, None)

    with pytest.raises(InvalidJwtTokenError):
        decode_token(token, settings)


def test_aud_is_not_checked_when_audience_unset(key_pair_str) -> None:
    """Backwards compatibility: existing deployments keep working (with a warning)."""
    settings = _settings(key_pair_str.public_key, audience=None)
    token = _token(key_pair_str.private_key, ["someone-else"])

    assert decode_token(token, settings).aud == ["someone-else"]


# --- algorithm pinning (RFC 8725) --------------------------------------------


def test_default_algorithms_exclude_symmetric_and_none() -> None:
    """The default allow-list must block the HS*/none confusion families.

    An RSA public key is public by definition, so permitting HS256 would let
    anyone use it as an HMAC secret and mint valid tokens.
    """
    settings = AuthentikateSettings(
        issuers=[{"kind": "rsa", "iss": ISS, "public_key": "unused"}],
    )

    assert not any(alg.startswith("HS") for alg in settings.algorithms)
    assert "none" not in settings.algorithms
    assert "RS256" in settings.algorithms


def test_algorithm_outside_the_allowlist_is_rejected(key_pair_str) -> None:
    """A token signed with an algorithm this service does not accept fails."""
    settings = AuthentikateSettings(
        issuers=[{"kind": "rsa", "iss": ISS, "public_key": key_pair_str.public_key}],
        algorithms=["ES256"],
    )
    token = _token(key_pair_str.private_key, None)  # RS256

    with pytest.raises(InvalidJwtTokenError):
        decode_token(token, settings)


@pytest.mark.parametrize("bad", [[], ["none"], ["NONE"], [" none "], ["RS256", "none"]])
def test_unsafe_algorithm_config_is_rejected(bad: list[str]) -> None:
    with pytest.raises(ValidationError):
        AuthentikateSettings(
            issuers=[{"kind": "rsa", "iss": ISS, "public_key": "unused"}],
            algorithms=bad,
        )


# --- the "*" wildcard --------------------------------------------------------


def test_wildcard_accepts_a_token_for_another_service(key_pair_str) -> None:
    """`AUDIENCE = "*"` is how a service says it accepts any audience."""
    settings = _settings(key_pair_str.public_key, audience="*")
    token = _token(key_pair_str.private_key, ["some-other-service"])

    assert decode_token(token, settings).aud == ["some-other-service"]


def test_wildcard_accepts_a_token_with_no_aud_claim(key_pair_str) -> None:
    """`"*"` must not end up *stricter* than leaving AUDIENCE unset.

    A literal audience makes `aud` an essential claim; the wildcard drops the
    constraint entirely, so a token without the claim is accepted too.
    """
    settings = _settings(key_pair_str.public_key, audience="*")
    token = _token(key_pair_str.private_key, None)

    assert decode_token(token, settings).aud is None


def test_wildcard_is_config_side_not_token_side(key_pair_str) -> None:
    """A token cannot award *itself* a wildcard.

    This is the security pin for the whole feature. If `"*"` were honoured in the
    `aud` claim, an issuer could mint one credential valid at every service --
    exactly the cross-service replay that audience checking exists to prevent.
    """
    settings = _settings(key_pair_str.public_key, audience="mikro")
    token = _token(key_pair_str.private_key, ["*"])

    with pytest.raises(InvalidJwtTokenError):
        decode_token(token, settings)


def test_a_literal_audience_is_unaffected_by_the_wildcard_support(key_pair_str) -> None:
    """Regression guard: configuring a real audience still enforces it."""
    settings = _settings(key_pair_str.public_key, audience="mikro")

    with pytest.raises(InvalidJwtTokenError):
        decode_token(_token(key_pair_str.private_key, ["fluss"]), settings)

    with pytest.raises(InvalidJwtTokenError):
        decode_token(_token(key_pair_str.private_key, None), settings)

    assert decode_token(_token(key_pair_str.private_key, ["mikro"]), settings)
