import base64
import json
from typing import Any
from joserfc import jwt
from authentikate import base_models, errors


def decode_token(
    token: str, settings: base_models.AuthentikateSettings
) -> base_models.JWTToken:
    """Decode a JWT token

    Parameters
    ----------
    token : str
        The token to decode
    algorithms : list
        The algorithms to use to decode the token
    public_key : str
        The public key to use to decode the token

    Returns
    -------
    structs.JWTToken
        The decoded token
    """
    try:
        decoded = jwt.decode(token, settings.load_key)
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidJwtTokenError("Error decoding token") from e

    try:
        return base_models.JWTToken(**{"raw": token, **decoded.claims})
    except TypeError as e:
        raise errors.MalformedJwtTokenError("Error decoding token") from e


def _decode_header(token: str) -> dict[str, Any]:
    """Decode the JWT header without verifying the token."""

    try:
        header_segment = token.split(".", maxsplit=1)[0]
        padding = "=" * (-len(header_segment) % 4)
        decoded_header = base64.urlsafe_b64decode(header_segment + padding)
        return json.loads(decoded_header)
    except Exception as e:
        raise errors.MalformedJwtTokenError("Error decoding token header") from e


async def adecode_token(
    token: str, settings: base_models.AuthentikateSettings
) -> base_models.JWTToken:
    """Decode a JWT token without blocking on remote JWKS retrieval."""

    try:
        header = _decode_header(token)
        kid = header.get("kid")
        if not kid:
            raise errors.MalformedJwtTokenError("Missing kid in header")

        decoded = jwt.decode(token, await settings.aload_key(kid))
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidJwtTokenError("Error decoding token") from e

    try:
        return base_models.JWTToken(**{"raw": token, **decoded.claims})
    except TypeError as e:
        raise errors.MalformedJwtTokenError("Error decoding token") from e
