"""The provenance-token decoder path (consuming / audience end).

Mirrors ``authentikate.decode`` for the auth token, but resolves keys from the
*provenance* issuer(s) — a separate trust domain with its own JWKS endpoint —
and pins the signature algorithm (``Ed25519`` by default, never ``none``), as
required by RFC 8725.
"""

import logging

from joserfc import jwt
from pydantic import ValidationError

from authentikate import base_models, errors
from authentikate.decode import _select_key_hints, _validate_claims
from authentikate.provenance.models import ProvenanceToken

logger = logging.getLogger(__name__)


def _build_token(token: str, claims: dict[str, object]) -> ProvenanceToken:
    """Build and validate a ProvenanceToken from decoded claims.

    ``raw`` is applied last so a token cannot spoof it via a ``raw`` claim; it
    always reflects the actual verified token string.
    """
    try:
        return ProvenanceToken(**{**claims, "raw": token})
    except (TypeError, ValidationError) as e:
        raise errors.MalformedProvenanceTokenError(
            "Error decoding provenance token"
        ) from e


def _check_audience(
    token: ProvenanceToken, provenance: base_models.ProvenanceSettings
) -> None:
    """Enforce that the configured service is in the token's audience.

    ``ANY_AUDIENCE`` accepts a token scoped to any service. The token must still
    *carry* an ``aud`` -- it is a required claim on ``ProvenanceToken`` -- but
    this verifier stops caring which service it names.

    The check is unconditional otherwise. It used to be guarded by
    ``if provenance.audience``, which made a blank configured audience skip it
    silently and accept a token minted for any other service;
    :func:`~authentikate.base_models.reject_blank_audience` now rejects that
    configuration at startup, and the guard is gone so a future blank value
    cannot re-open the check.
    """
    if provenance.audience == base_models.ANY_AUDIENCE:
        return

    if not token.has_audience(provenance.audience):
        raise errors.ProvenanceAudienceError(
            f"Provenance token audience {token.aud} does not include "
            f"{provenance.audience!r}"
        )


def decode_provenance_token(
    token: str, settings: base_models.AuthentikateSettings
) -> ProvenanceToken:
    """Decode and verify a provenance token.

    Verifies the Ed25519 signature against the configured provenance issuers,
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

    iss, kid = _select_key_hints(token)

    try:
        key_set = provenance.resolve_key_set(iss, kid)
        decoded = jwt.decode(token, key_set, algorithms=provenance.algorithms)
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidProvenanceTokenError(
            "Error decoding provenance token"
        ) from e

    # Audience is enforced by _check_audience below, which reports the
    # specific ProvenanceAudienceError rather than a generic claim failure.
    _validate_claims(decoded, issuer=iss)

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

    iss, kid = _select_key_hints(token)

    try:
        key_set = await provenance.aresolve_key_set(iss, kid)
        decoded = jwt.decode(token, key_set, algorithms=provenance.algorithms)
    except (errors.AuthentikateError, errors.AuthentikatePermissionDenied) as e:
        raise e
    except Exception as e:
        raise errors.InvalidProvenanceTokenError(
            "Error decoding provenance token"
        ) from e

    # Audience is enforced by _check_audience below, which reports the
    # specific ProvenanceAudienceError rather than a generic claim failure.
    _validate_claims(decoded, issuer=iss)

    built = _build_token(token, decoded.claims)
    _check_audience(built, provenance)
    # Never log the token itself -- `raw` is a bearer credential.
    logger.debug("Verified provenance token jti=%s tsk=%s", built.jti, built.tsk)
    return built
