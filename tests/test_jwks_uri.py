import json
import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from authentikate.base_models import JWKSUriIssuer, AuthentikateSettings
from authentikate.decode import decode_token
from joserfc.jwk import RSAKey
from joserfc import jwt


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


def test_jwks_uri_issuer_fetching(key_pair_str):

    # helper to make a strict jwk
    rsa_key = RSAKey.import_key(key_pair_str.public_key)
    jwk_dict = rsa_key.as_dict(kid="1")
    jwks = {"keys": [jwk_dict]}

    session = _build_mock_session(jwks)

    with patch("authentikate.base_models.httpx.AsyncClient", return_value=session):

        issuer = JWKSUriIssuer(
            kind="jwks_uri",
            iss="http://test-issuer",
            jwks_uri="http://test-issuer/.well-known/jwks.json",
        )

        keys = issuer.get_as_jwks()
        assert len(keys) == 1
        assert keys[0]["kid"] == "1"

        session.get.assert_called_with("http://test-issuer/.well-known/jwks.json")


def test_jwks_uri_integration(key_pair_str):
    # Test valid decoding using the settings
    rsa_key = RSAKey.import_key(key_pair_str.public_key)
    jwk_dict = rsa_key.as_dict(kid="test-kid")
    jwks = {"keys": [jwk_dict]}

    session = _build_mock_session(jwks)

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

        fetched_keys = settings.get_jwks()
        assert len(fetched_keys) == 1
        assert fetched_keys[0]["kid"] == "test-kid"


def test_jwks_uri_decoding(key_pair_str):
    # Test full decoding flow
    rsa_key = RSAKey.import_key(key_pair_str.public_key)
    # We need the private key to sign

    # We need to construct a token signed with the private key
    # Use joserfc to encode

    # Load private key for signing
    private_key_obj = RSAKey.import_key(key_pair_str.private_key)

    header = {"kid": "test-kid", "alg": "RS256"}
    now = datetime.datetime.now(datetime.timezone.utc)
    claims = {
        "sub": "user1",
        "iss": "http://test-issuer",
        "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
        "iat": int(now.timestamp()),
        "client_id": "test-client",
        "preferred_username": "testuser",
        "roles": ["user"],
        "scope": "openid profile",
    }

    token = jwt.encode(header, claims, private_key_obj)

    jwk_dict = rsa_key.as_dict(kid="test-kid")
    jwks = {"keys": [jwk_dict]}

    session = _build_mock_session(jwks)

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

        decoded_token = decode_token(token, settings)
        assert decoded_token.sub == "user1"
        assert decoded_token.iss == "http://test-issuer"
