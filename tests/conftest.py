from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pytest_django.fixtures import SettingsWrapper
import dataclasses
import pytest
import datetime
from joserfc import jwt
import uuid
from joserfc.jwk import RSAKey
from authentikate.base_models import AuthentikateSettings, Issuer, RSAKeyIssuer, JWKIssuer


# Generate a private key


@dataclasses.dataclass
class KeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey


@dataclasses.dataclass
class KeyPairStr:
    private_key: str
    public_key: str


@pytest.fixture(scope="session")
def private_key():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


@pytest.fixture(scope="session")
def key_pair(private_key) -> KeyPair:
    public_key = private_key.public_key()

    return KeyPair(private_key=private_key, public_key=public_key)


@pytest.fixture(scope="session")
def key_pair_str(private_key) -> KeyPairStr:
    # Generate the public key
    public_key = private_key.public_key()

    # Serializing the private and public key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return KeyPairStr(private_key=pem_private, public_key=pem_public)


@pytest.fixture(scope="session")
def valid_claims():
    return {
        "sub": "1",
        "iss": "XXXX",
        "jti": uuid.uuid4().hex,
        "iat": int(datetime.datetime.now().timestamp()),  # issued at
        "exp": int(
            (datetime.datetime.now() + datetime.timedelta(days=1)).timestamp()
        ),
        "preferred_username": "farter",
        "client_id": "XXXX",
        "scope": "openid profile email read",
        "roles": ["XXXX"],
        "active_org": "kkk",
    }


@pytest.fixture(scope="session")
def valid_jwt(valid_claims, key_pair_str: KeyPairStr):
    
    key = RSAKey.import_key(key_pair_str.private_key)
    
    header = {"alg": "RS256", "kid": "1"}
    return jwt.encode(
        header,
        valid_claims,
        key,
    )
    
    
@pytest.fixture(scope="session")
def valid_settings(key_pair_str: KeyPairStr):
    
    key = RSAKey.import_key(key_pair_str.public_key)
    
    
    return AuthentikateSettings(
        issuers=[
            JWKIssuer(
                iss="XXXX",
                jwks={
                    "keys": [
                        key.as_dict(kid="1"),
                    ]
                }
            )
        ]
    )
    
@pytest.fixture(scope="session")
def valid_rsa_key(key_pair_str: KeyPairStr):
    
    return AuthentikateSettings(
        issuers=[
            RSAKeyIssuer(
                iss="XXXX",
                key=key_pair_str.public_key,
            )
        ]
    )
    
    
@pytest.fixture(scope="session")
def valid_decode_key(key_pair_str: KeyPairStr):
    return RSAKey.import_key(key_pair_str.public_key)


@pytest.fixture(scope="session")
def valid_auth_headers(valid_jwt):
    return {
        "Authorization": f"Bearer {valid_jwt}",
    }