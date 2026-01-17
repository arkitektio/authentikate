from unittest.mock import MagicMock, patch
from authentikate.base_models import JWKSUriIssuer
from joserfc.jwk import RSAKey
import json

def test_jwks_uri_caching_logic(key_pair_str):
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
        
        # First call fetches
        keys1 = issuer.get_as_jwks()
        assert len(keys1) == 1
        assert mock_urlopen.call_count == 1
        
        # Second call uses cache
        keys2 = issuer.get_as_jwks()
        assert len(keys2) == 1
        assert mock_urlopen.call_count == 1
        
        # Explicit refresh
        issuer.refresh()
        assert mock_urlopen.call_count == 2

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

    mock_response1 = MagicMock()
    mock_response1.read.return_value = json.dumps(jwks1).encode("utf-8")
    mock_response1.__enter__.return_value = mock_response1
    
    mock_response2 = MagicMock()
    mock_response2.read.return_value = json.dumps(jwks2).encode("utf-8")
    mock_response2.__enter__.return_value = mock_response2

    with patch("urllib.request.urlopen", side_effect=[mock_response1, mock_response2]) as mock_urlopen:
        
        settings = AuthentikateSettings(
            issuers=[
                {
                    "kind": "jwks_uri",
                    "iss": "http://test-issuer",
                    "jwks_uri": "http://test-issuer/jwks"
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
            "scope": "scope"
        }

        header1 = {"kid": "1", "alg": "RS256"}
        token1 = jwt.encode(header1, claims, private_key_obj)
        
        decode_token(token1, settings)
        assert mock_urlopen.call_count == 1 # Fetched once
        
        # Decode again with kid="1" - should use cache
        decode_token(token1, settings)
        assert mock_urlopen.call_count == 1 # Still 1
        
        # Now token with kid="2"
        header2 = {"kid": "2", "alg": "RS256"}
        token2 = jwt.encode(header2, claims, private_key_obj)
        
        decode_token(token2, settings)
        
        # Should have refreshed
        assert mock_urlopen.call_count == 2
