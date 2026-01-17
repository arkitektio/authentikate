
import pytest
from unittest.mock import MagicMock, patch
from authentikate.errors import (
    NoAuthorizationHeader,
    MalformedAuthorizationHeader,
    JwksError,
    MalformedJwtTokenError,
    InvalidJwtTokenError
)
from authentikate.utils import authenticate_header
from authentikate.base_models import AuthentikateSettings, JWKSUriIssuer
from authentikate.decode import decode_token
import urllib.error
import urllib.request
from joserfc import jwt
from joserfc.jwk import RSAKey
import datetime
import json

def test_no_authorization_header():
    settings = AuthentikateSettings(issuers=[])
    headers = {"Content-Type": "application/json"}
    
    with pytest.raises(NoAuthorizationHeader):
        authenticate_header(headers, settings)

def test_malformed_authorization_header():
    settings = AuthentikateSettings(issuers=[])
    headers = {"Authorization": "Basic 123456"}
    
    with pytest.raises(MalformedAuthorizationHeader):
        authenticate_header(headers, settings)


def test_jwks_fetch_error():
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.URLError("Failed")
        
        issuer = JWKSUriIssuer(
            kind="jwks_uri",
            iss="http://test",
            jwks_uri="http://test/jwks"
        )
        
        with pytest.raises(JwksError) as excinfo:
            issuer.get_as_jwks()
        
        assert "Error fetching jwks" in str(excinfo.value)

def test_missing_kid_in_header(key_pair_str):
    # Create a token without kid
    rsa_key = RSAKey.import_key(key_pair_str.private_key)
    header = {"alg": "RS256"} # No kid
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
    jwks = {"keys": [jwk_dict]}
    
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(jwks).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        settings = AuthentikateSettings(
            issuers=[
                {
                    "kind": "jwks_uri",
                    "iss": "http://test",
                    "jwks_uri": "http://test/jwks"
                }
            ]
        )
        
        with pytest.raises(InvalidJwtTokenError):
            decode_token(token, settings)


# We need to verify that decode_token propagates or wraps the Authentikate errors correctly
# If load_key raises MalformedJwtTokenError (which is a JwtTokenError -> AuthentikatePermissionDenied)
# decode_token might catch it as "Exception" and wrap it in InvalidJwtTokenError.

