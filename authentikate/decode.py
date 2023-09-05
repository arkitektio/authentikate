import jwt
from authentikate import errors, structs
from pydantic import BaseModel
from typing import Type


def decode_token(
    token: str,
    settings: structs.AuthentikateSettings,
) -> structs.JWTToken:
    try:
        decoded = jwt.decode(token, settings.public_key, algorithms=settings.algorithms)
    except Exception as e:
        raise errors.InvalidJwtTokenError("Error decoding token") from e

    try:
        return settings.jwt_base_model(**decoded)
    except TypeError as e:
        raise errors.MalformedJwtTokenError("Error decoding token") from e
