"""The provenance-token decoder path (consuming / audience end).

Mirrors ``authentikate.decode`` for the auth token, but resolves keys from the
*provenance* issuer(s) — a separate trust domain with its own JWKS endpoint —
and pins the signature algorithm (``EdDSA`` by default, never ``none``), as
required by RFC 8725.
"""

from joserfc import jwt
from pydantic import ValidationError

from authentikate import base_models, errors
from authentikate.decode import _decode_header, _validate_claims
from authentikate.provenance.models import ProvenanceToken


def _build_token(token: str, claims: dict[str, object]) -> ProvenanceToken:
    """Build and validate a ProvenanceToken from decoded claims."""
    try:
        return ProvenanceToken(**{"raw": token, **claims})
    except (TypeError, ValidationError) as e:
        raise errors.MalformedProvenanceTokenError(
            "Error decoding provenance token"
        ) from e


def _check_audience(
    token: ProvenanceToken, provenance: base_models.ProvenanceSettings
) -> None:
    """Enforce that the configured service is in the token's audience."""
    if provenance.audience and not token.has_audience(provenance.audience):
        raise errors.ProvenanceAudienceError(
            f"Provenance token audience {token.aud} does not include "
            f"{provenance.audience!r}"
        )


def decode_provenance_token(
    token: str, settings: base_models.AuthentikateSettings
) -> ProvenanceToken:
    """Decode and verify a provenance token.

    Verifies the EdDSA signature against the configured provenance issuers,
    validates the registered claims (expiry), and checks audience membership.

    Raises
    ------
    ProvenanceNotConfiguredError
        When no provenance issuers are configured.
    InvalidProvenanceTokenError
        When the signature or claims are invalid.
    AuthentikateTokenExpired
        When the token is expired.
    MalformedProvenanceTokenError
        When the payload does not form a valid ProvenanceToken.
    ProvenanceAudienceError
        When the configured service is not in the token's audience.
    """
    provenance = settings.provenance
    if provenance is None:
        raise errors.ProvenanceNotConfiguredError("Provenance is not configured")

    try:
        decoded = jwt.decode(
            token, provenance.load_key, algorithms=provenance.algorithms
        )
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidProvenanceTokenError(
            "Error decoding provenance token"
        ) from e

    _validate_claims(decoded)

    built = _build_token(token, decoded.claims)
    _check_audience(built, provenance)
    return built


async def adecode_provenance_token(
    token: str, settings: base_models.AuthentikateSettings
) -> ProvenanceToken:
    """Decode a provenance token without blocking on remote JWKS retrieval."""

    provenance = settings.provenance
    if provenance is None:
        raise errors.ProvenanceNotConfiguredError("Provenance is not configured")

    try:
        header = _decode_header(token)
        kid = header.get("kid")
        if not kid:
            raise errors.MalformedProvenanceTokenError("Missing kid in header")

        decoded = jwt.decode(
            token,
            await provenance.aload_key(kid),
            algorithms=provenance.algorithms,
        )
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidProvenanceTokenError(
            "Error decoding provenance token"
        ) from e

    _validate_claims(decoded)

    built = _build_token(token, decoded.claims)
    _check_audience(built, provenance)
    return built
