import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from authentikate.errors import (
    NoAuthorizationHeader,
    MalformedAuthorizationHeader,
    JwksError,
    MalformedJwtTokenError,
    InvalidJwtTokenError,
)
from authentikate.utils import (
    authenticate_header,
    authenticate_header_or_none,
    authenticate_token_or_none,
)
from authentikate.base_models import AuthentikateSettings, JWKSUriIssuer
from authentikate.decode import decode_token
from joserfc import jwt
from joserfc.jwk import RSAKey
import datetime


def _build_mock_session(*responses_or_exceptions):
    session = AsyncMock()
    session.__aenter__.return_value = session
    session.__aexit__.return_value = False

    managers = []
    for item in responses_or_exceptions:
        if isinstance(item, Exception):
            managers.append(item)
            continue

        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = item
        managers.append(response)

    session.get.side_effect = managers
    return session


@pytest.mark.asyncio
async def test_no_authorization_header():
    settings = AuthentikateSettings(issuers=[])
    headers = {"Content-Type": "application/json"}

    with pytest.raises(NoAuthorizationHeader):
        await authenticate_header(headers, settings)


@pytest.mark.asyncio
async def test_malformed_authorization_header():
    settings = AuthentikateSettings(issuers=[])
    headers = {"Authorization": "Basic 123456"}

    with pytest.raises(MalformedAuthorizationHeader):
        await authenticate_header(headers, settings)


@pytest.mark.asyncio
async def test_authenticate_header_or_none_returns_none_for_auth_failure():
    settings = AuthentikateSettings(issuers=[])
    headers = {"Content-Type": "application/json"}

    assert await authenticate_header_or_none(headers, settings) is None


@pytest.mark.asyncio
async def test_authenticate_header_or_none_reraises_unexpected_errors():
    with patch(
        "authentikate.utils.authenticate_header",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        with pytest.raises(RuntimeError, match="boom"):
            await authenticate_header_or_none({}, None)


@pytest.mark.asyncio
async def test_authenticate_token_or_none_reraises_unexpected_errors():
    with patch(
        "authentikate.utils.authenticate_token",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        with pytest.raises(RuntimeError, match="boom"):
            await authenticate_token_or_none("token", None)


def test_jwks_fetch_error():
    session = _build_mock_session(Exception("Failed"))
    with patch("authentikate.base_models.httpx.AsyncClient", return_value=session):

        issuer = JWKSUriIssuer(
            kind="jwks_uri", iss="http://test", jwks_uri="http://test/jwks"
        )

        with pytest.raises(JwksError) as excinfo:
            issuer.get_as_jwks()

        assert "Error fetching jwks" in str(excinfo.value)


def test_missing_kid_in_header(key_pair_str):
    # Create a token without kid
    rsa_key = RSAKey.import_key(key_pair_str.private_key)
    header = {"alg": "RS256"}  # No kid
    claims = {"sub": "user"}
    token = jwt.encode(header, claims, rsa_key)

    settings = AuthentikateSettings(issuers=[])

    # decode_token catches exceptions and re-raises them specific authentikate errors
    # But here the error happens inside load_key which is called by jwt.decode
    # base_models.py load_key raises MalformedJwtTokenError if kid is missing

    # However, decode_token implementation catches Exception and raises InvalidJwtTokenError or MalformedJwtTokenError
    # Let's check decode.py again.

    with pytest.raises(MalformedJwtTokenError):
        # We need to bypass decode_token wrapper if we want to see the exact exception from load_key,
        # OR we check if decode_token wraps it correctly.
        # decode_token catches "Exception"
        decode_token(token, settings)


def test_key_not_found(key_pair_str):
    # Token signed with key "1"
    private_key_obj = RSAKey.import_key(key_pair_str.private_key)
    header = {"kid": "1", "alg": "RS256"}
    claims = {"sub": "user"}
    token = jwt.encode(header, claims, private_key_obj)

    # Settings with Key "2"
    rsa_key = RSAKey.import_key(key_pair_str.public_key)
    jwk_dict = rsa_key.as_dict(kid="2")
    session = _build_mock_session({"keys": [jwk_dict]}, {"keys": [jwk_dict]})

    with patch("authentikate.base_models.httpx.AsyncClient", return_value=session):
        settings = AuthentikateSettings(
            issuers=[
                JWKSUriIssuer(
                    kind="jwks_uri",
                    iss="http://test",
                    jwks_uri="http://test/jwks",
                )
            ]
        )

        with pytest.raises(InvalidJwtTokenError):
            decode_token(token, settings)


# We need to verify that decode_token propagates or wraps the Authentikate errors correctly
# If load_key raises MalformedJwtTokenError (which is a JwtTokenError -> AuthentikatePermissionDenied)
# decode_token might catch it as "Exception" and wrap it in InvalidJwtTokenError.
