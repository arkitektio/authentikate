"""A service names itself only within its hub (``aud: mikro``), so the hub tells two hubs' services apart.

A service that knows its hub (``AUTHENTIKATE.HUB``) accepts a token only when its ``hub``
claim is that hub; one that belongs to no hub does not check it.
"""

import datetime

import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from authentikate.base_models import AuthentikateSettings
from authentikate.decode import adecode_token, decode_token
from authentikate.errors import InvalidJwtTokenError

ISS = "https://idp.example"
HUB = "0192f3c4-7a2b-7c1d-9e8f-1a2b3c4d5e6f"
OTHER_HUB = "0192f3c4-0000-7000-8000-000000000000"


def _settings(public_key: str, hub: str | None) -> AuthentikateSettings:
    return AuthentikateSettings(issuers=[{"kind": "rsa", "iss": ISS, "public_key": public_key}], audience="mikro", hub=hub)


def _token(private_key: str, hub: str | None) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    claims: dict[str, object] = {
        "sub": "1",
        "iss": ISS,
        "aud": ["lok", "mikro", "rekuest"],
        "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "client_id": "client",
        "preferred_username": "user",
        "roles": ["user"],
        "scope": "openid",
    }
    if hub is not None:
        claims["hub"] = hub
    return jwt.encode({"alg": "RS256", "kid": "1"}, claims, RSAKey.import_key(private_key))


def test_a_token_for_this_hubs_service_is_accepted(key_pair_str) -> None:
    token = decode_token(_token(key_pair_str.private_key, HUB), _settings(key_pair_str.public_key, HUB))
    assert token.hub == HUB


def test_a_token_for_the_same_service_of_another_hub_is_refused(key_pair_str) -> None:
    with pytest.raises(InvalidJwtTokenError):
        decode_token(_token(key_pair_str.private_key, OTHER_HUB), _settings(key_pair_str.public_key, HUB))


def test_a_token_naming_no_hub_is_refused_where_the_service_has_one(key_pair_str) -> None:
    with pytest.raises(InvalidJwtTokenError):
        decode_token(_token(key_pair_str.private_key, None), _settings(key_pair_str.public_key, HUB))


@pytest.mark.asyncio
async def test_the_async_path_checks_the_hub_too(key_pair_str) -> None:
    with pytest.raises(InvalidJwtTokenError):
        await adecode_token(_token(key_pair_str.private_key, OTHER_HUB), _settings(key_pair_str.public_key, HUB))


def test_a_service_of_no_hub_does_not_check_it(key_pair_str) -> None:
    """The coordination server itself belongs to no hub."""
    settings = _settings(key_pair_str.public_key, None)
    assert decode_token(_token(key_pair_str.private_key, OTHER_HUB), settings).hub == OTHER_HUB
    assert decode_token(_token(key_pair_str.private_key, None), settings).hub is None
