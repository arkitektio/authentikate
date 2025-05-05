from authentikate.models import User
from authentikate.decode import decode_token



def test_authenticate_token(db, valid_jwt, key_pair):
    token = decode_token(valid_jwt, ["RS256"], key_pair.public_key)
    assert token.sub == "1", "User ID should be 1"
    assert token.client_id == "XXXX", "Client ID should be 'XXXX'"
