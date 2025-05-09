from authentikate.models import User
from authentikate.decode import decode_token



def test_authenticate_token(db, valid_jwt, valid_settings):
    token = decode_token(valid_jwt, valid_settings)
    assert token.sub == "1", "User ID should be 1"
    assert token.client_id == "XXXX", "Client ID should be 'XXXX'"
