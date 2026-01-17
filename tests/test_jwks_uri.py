import json
import datetime
from unittest.mock import MagicMock, patch
from authentikate.base_models import JWKSUriIssuer, AuthentikateSettings
from authentikate.decode import decode_token
from joserfc.jwk import RSAKey
from joserfc import jwt

def test_jwks_uri_issuer_fetching(key_pair_str):
    
    # helper to make a strict jwk
    rsa_key = RSAKey.import_key(key_pair_str.public_key)
    jwk_dict = rsa_key.as_dict(kid="1")
    jwks = {"keys": [jwk_dict]}
    
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(jwks).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
        
        issuer = JWKSUriIssuer(
            kind="jwks_uri",
            iss="http://test-issuer",
            jwks_uri="http://test-issuer/.well-known/jwks.json"
        )
        
        keys = issuer.get_as_jwks()
        assert len(keys) == 1
        assert keys[0]["kid"] == "1"
        
        mock_urlopen.assert_called_with("http://test-issuer/.well-known/jwks.json")

def test_jwks_uri_integration(key_pair_str):
    # Test valid decoding using the settings
    rsa_key = RSAKey.import_key(key_pair_str.public_key)
    jwk_dict = rsa_key.as_dict(kid="test-kid")
    jwks = {"keys": [jwk_dict]}
    
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(jwks).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        
        settings = AuthentikateSettings(
            issuers=[
                {
                    "kind": "jwks_uri",
                    "iss": "http://test-issuer",
                    "jwks_uri": "http://test-issuer/jwks"
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

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(jwks).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):

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

