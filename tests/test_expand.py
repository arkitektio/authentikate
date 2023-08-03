from authentikate.models import User
from authentikate.expand import expand_token
from authentikate.decode import decode_token
import jwt


def test_authenticate_token(db, valid_jwt, key_pair):
    token = decode_token(valid_jwt, ["RS256"], key_pair.public_key)
    x = expand_token(token, force_client=False)
    assert x.user.sub == "1", "User ID should be 1"
