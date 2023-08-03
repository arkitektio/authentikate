from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pytest_django.fixtures import SettingsWrapper
import dataclasses
import pytest
import datetime
import jwt

# Generate a private key


@dataclasses.dataclass
class KeyPair:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey


@pytest.fixture(scope="session")
def key_pair() -> KeyPair:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    return KeyPair(private_key=private_key, public_key=public_key)


@pytest.fixture(scope="session")
def valid_claims():
    return {
        "sub": 1,
        "iss": "XXXX",
        "iat": int(datetime.datetime.utcnow().timestamp()),  # issued at
        "exp": int(
            (datetime.datetime.utcnow() + datetime.timedelta(days=1)).timestamp()
        ),
        "preferred_username": "farter",
        "client_id": "XXXX",
        "scope": "openid profile email",
        "roles": ["XXXX"],
    }


@pytest.fixture(scope="session")
def valid_jwt(valid_claims, key_pair: KeyPair):
    print(key_pair.private_key)
    return jwt.encode(
        valid_claims,
        key=key_pair.private_key,
        algorithm="RS256",
    )
