import base64
import json
from typing import Any
from joserfc import jwt
from joserfc.errors import ExpiredTokenError
from pydantic import ValidationError
from authentikate import base_models, errors


def _validate_claims(
    decoded: jwt.Token,
    issuer: str | None = None,
    audience: str | None = None,
) -> None:
    """Validate the registered claims of a decoded token.

    ``exp`` is always essential. ``issuer`` confirms the verified token really
    carries the ``iss`` its key was selected by, and ``audience`` confirms the
    token was minted for this service; both are skipped when not supplied.
    """
    # The registry pins "now" at construction time, so it must be created
    # per validation rather than once at module level.
    claims_options: dict[str, Any] = {"exp": {"essential": True}}

    if issuer is not None:
        claims_options["iss"] = {"essential": True, "value": issuer}

    if audience is not None:
        # joserfc treats a scalar "value" for aud as membership in a
        # list-valued claim, so this handles both aud shapes.
        claims_options["aud"] = {"essential": True, "value": audience}

    registry = jwt.JWTClaimsRegistry(**claims_options)
    try:
        registry.validate(decoded.claims)
    except ExpiredTokenError as e:
        raise errors.AuthentikateTokenExpired("Token has expired") from e
    except Exception as e:
        raise errors.InvalidJwtTokenError("Token claims are invalid") from e


def _decode_segment(token: str, index: int, what: str) -> dict[str, Any]:
    """Base64url-decode one JWT segment into a dict, without verifying anything."""

    try:
        segment = token.split(".")[index]
        padding = "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(segment + padding)
        loaded = json.loads(decoded)
    except Exception as e:
        raise errors.MalformedJwtTokenError(f"Error decoding token {what}") from e

    if not isinstance(loaded, dict):
        raise errors.MalformedJwtTokenError(f"Token {what} is not an object")

    return loaded


def _decode_header(token: str) -> dict[str, Any]:
    """Decode the JWT header without verifying the token."""

    return _decode_segment(token, 0, "header")


def _select_key_hints(token: str) -> tuple[str, str]:
    """Read the ``iss`` claim and ``kid`` header used to pick a verification key.

    Nothing read here is trusted -- it only selects *which* issuer's keys the
    signature is then checked against. ``_validate_claims`` re-checks ``iss``
    against that issuer once the signature has been verified.
    """

    kid = _decode_header(token).get("kid")
    if not kid or not isinstance(kid, str):
        raise errors.MalformedJwtTokenError("Missing kid in header")

    iss = _decode_segment(token, 1, "payload").get("iss")
    if not iss or not isinstance(iss, str):
        raise errors.MalformedJwtTokenError("Missing iss claim in token")

    return iss, kid


def decode_token(
    token: str, settings: base_models.AuthentikateSettings
) -> base_models.JWTToken:
    """Decode and verify a JWT token

    The token's ``iss`` claim selects which configured issuer's keys the
    signature is verified against, so a token can never be verified with a
    different issuer's key. The registered claims (expiry, issuer, and audience
    when configured) are validated afterwards.

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
        When the issuer is untrusted, or the signature or claims are invalid
    AuthentikateTokenExpired
        When the token is expired
    MalformedJwtTokenError
        When the token payload does not form a valid JWTToken
    """
    iss, kid = _select_key_hints(token)

    try:
        key_set = settings.resolve_key_set(iss, kid)
        decoded = jwt.decode(token, key_set, algorithms=settings.algorithms)
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidJwtTokenError("Error decoding token") from e

    _validate_claims(decoded, issuer=iss, audience=settings.audience)

    try:
        return base_models.JWTToken(**{**decoded.claims, "raw": token})
    except (TypeError, ValidationError) as e:
        raise errors.MalformedJwtTokenError("Error decoding token") from e


async def adecode_token(
    token: str, settings: base_models.AuthentikateSettings
) -> base_models.JWTToken:
    """Decode a JWT token without blocking on remote JWKS retrieval."""

    iss, kid = _select_key_hints(token)

    try:
        key_set = await settings.aresolve_key_set(iss, kid)
        decoded = jwt.decode(token, key_set, algorithms=settings.algorithms)
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidJwtTokenError("Error decoding token") from e

    _validate_claims(decoded, issuer=iss, audience=settings.audience)

    try:
        return base_models.JWTToken(**{**decoded.claims, "raw": token})
    except (TypeError, ValidationError) as e:
        raise errors.MalformedJwtTokenError("Error decoding token") from e
