from authentikate.models import User
from authentikate.decode import decode_token


def test_decode_token(valid_jwt, valid_settings):
    token = decode_token(valid_jwt, valid_settings)
    assert token.client_id == "XXXX"
