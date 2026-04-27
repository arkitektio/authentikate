from unittest.mock import AsyncMock, MagicMock, patch
from authentikate.base_models import JWKSUriIssuer
from joserfc.jwk import RSAKey


def _build_mock_session(*payloads):
    session = AsyncMock()
    session.__aenter__.return_value = session
    session.__aexit__.return_value = False

    responses = []
    for payload in payloads:
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = payload
        responses.append(response)

    session.get.side_effect = responses
    return session


def test_jwks_uri_caching_logic(key_pair_str):
    rsa_key = RSAKey.import_key(key_pair_str.public_key)
    jwk_dict = rsa_key.as_dict(kid="1")
    jwks = {"keys": [jwk_dict]}

    session = _build_mock_session(jwks, jwks)

    with patch("authentikate.base_models.httpx.AsyncClient", return_value=session):

        issuer = JWKSUriIssuer(
            kind="jwks_uri",
            iss="http://test-issuer",
            jwks_uri="http://test-issuer/.well-known/jwks.json",
        )

        # First call fetches
        keys1 = issuer.get_as_jwks()
        assert len(keys1) == 1
        assert session.get.call_count == 1

        # Second call uses cache
        keys2 = issuer.get_as_jwks()
        assert len(keys2) == 1
        assert session.get.call_count == 1

        # Explicit refresh
        issuer.refresh()
        assert session.get.call_count == 2


from authentikate.base_models import AuthentikateSettings
from authentikate.decode import decode_token
from joserfc import jwt
import datetime


def test_jwks_uri_refresh_on_missing_kid(key_pair_str):
    rsa_key = RSAKey.import_key(key_pair_str.public_key)

    # Key 1
    jwk_dict1 = rsa_key.as_dict(kid="1")
    jwks1 = {"keys": [jwk_dict1]}

    # Key 2 exists only in second response
    jwk_dict2 = rsa_key.as_dict(kid="2")
    jwks2 = {"keys": [jwk_dict1, jwk_dict2]}

    session = _build_mock_session(jwks1, jwks2)

    with patch("authentikate.base_models.httpx.AsyncClient", return_value=session):

        settings = AuthentikateSettings(
            issuers=[
                {
                    "kind": "jwks_uri",
                    "iss": "http://test-issuer",
                    "jwks_uri": "http://test-issuer/jwks",
                }
            ]
        )

        # 1. First token with kid="1"
        # We need a token that is valid otherwise so we can reach the key loading part

        private_key_obj = RSAKey.import_key(key_pair_str.private_key)
        now = datetime.datetime.now(datetime.timezone.utc)
        claims = {
            "sub": "user",
            "iss": "http://test-issuer",
            "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
            "iat": int(now.timestamp()),
            "client_id": "client",
            "preferred_username": "user",
            "roles": ["user"],
            "scope": "scope",
        }

        header1 = {"kid": "1", "alg": "RS256"}
        token1 = jwt.encode(header1, claims, private_key_obj)

        decode_token(token1, settings)
        assert session.get.call_count == 1  # Fetched once

        # Decode again with kid="1" - should use cache
        decode_token(token1, settings)
        assert session.get.call_count == 1  # Still 1

        # Now token with kid="2"
        header2 = {"kid": "2", "alg": "RS256"}
        token2 = jwt.encode(header2, claims, private_key_obj)

        decode_token(token2, settings)

        # Should have refreshed
        assert session.get.call_count == 2
