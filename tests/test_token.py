from authentikate.base_models import AuthentikateSettings
from authentikate.decode import decode_token


def test_decode_token(valid_jwt: str, valid_settings: AuthentikateSettings) -> None:
    token = decode_token(valid_jwt, valid_settings)
    assert token.client_id == "XXXX"
