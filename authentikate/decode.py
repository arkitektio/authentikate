import base64
import json
from typing import Any
from joserfc import jwt
from joserfc.errors import ExpiredTokenError
from pydantic import ValidationError
from authentikate import base_models, errors


def _validate_claims(decoded: jwt.Token) -> None:
    """Validate registered claims (e.g. expiry) of a decoded token."""
    # The registry pins "now" at construction time, so it must be created
    # per validation rather than once at module level.
    registry = jwt.JWTClaimsRegistry(exp={"essential": True})
    try:
        registry.validate(decoded.claims)
    except ExpiredTokenError as e:
        raise errors.AuthentikateTokenExpired("Token has expired") from e
    except Exception as e:
        raise errors.InvalidJwtTokenError("Token claims are invalid") from e


def decode_token(
    token: str, settings: base_models.AuthentikateSettings
) -> base_models.JWTToken:
    """Decode and verify a JWT token

    Verifies the signature against the issuers configured in the settings
    and validates the registered claims (e.g. expiry).

    Parameters
    ----------
    token : str
        The raw token string to decode
    settings : base_models.AuthentikateSettings
        The settings holding the trusted issuers and their keys

    Returns
    -------
    base_models.JWTToken
        The decoded token

    Raises
    ------
    InvalidJwtTokenError
        When the signature or claims are invalid
    AuthentikateTokenExpired
        When the token is expired
    MalformedJwtTokenError
        When the token payload does not form a valid JWTToken
    """
    try:
        decoded = jwt.decode(token, settings.load_key)
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidJwtTokenError("Error decoding token") from e

    _validate_claims(decoded)

    try:
        return base_models.JWTToken(**{"raw": token, **decoded.claims})
    except (TypeError, ValidationError) as e:
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

    _validate_claims(decoded)

    try:
        return base_models.JWTToken(**{"raw": token, **decoded.claims})
    except (TypeError, ValidationError) as e:
        raise errors.MalformedJwtTokenError("Error decoding token") from e
