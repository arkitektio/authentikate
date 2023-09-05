from authentikate.models import User
from authentikate.structs import AuthentikateSettings
from authentikate.expand import expand_token
from authentikate.decode import decode_token
import jwt


def test_authenticate_token(db, valid_jwt, key_pair):
    settings = AuthentikateSettings(
        algorithms=["RS256"],
        public_key=key_pair.public_key,
        allow_imitate=True,
        force_client=False,
    )

    token = decode_token(valid_jwt, settings)
    x = expand_token(token, settings)
    assert x.user.sub == "1", "User ID should be 1"
