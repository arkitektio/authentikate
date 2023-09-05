from authentikate.models import User
from authentikate.decode import decode_token
import jwt


def test_decode_token(valid_jwt, key_pair):
    token = decode_token(valid_jwt, key_pair.public_key, ["RS256"])
    assert token.client_id == "XXXX"
