"""Verifier helpers for provenance tokens (consuming / audience end).

These cover the verifier responsibilities the issuing spec leaves downstream:
actor-binding (``act`` vs the presenting agent's auth token) and ``ahs``
recomputation against the cleartext args. Single-use ``jti`` enforcement and the
provenance store need a database and remain the host application's job; the
``jti`` claim is exposed on :class:`ProvenanceToken` for that purpose.
"""

import logging
from typing import Any

from authentikate import errors
from authentikate.base_models import AuthentikateSettings, JWTToken
from authentikate.provenance.decode import adecode_provenance_token
from authentikate.provenance.models import ProvenanceToken
from authentikate.settings import get_settings

logger = logging.getLogger(__name__)

__all__ = [
    "verify_actor",
    "verify_args",
    "aauthenticate_provenance_header",
    "aauthenticate_provenance_header_or_none",
]


def verify_actor(provenance: ProvenanceToken, auth_token: JWTToken) -> None:
    """Bind a provenance token's actor to the presenting agent's auth token.

    The provenance token names the executing agent in ``act``; this confirms the
    auth token presented alongside it really belongs to that agent.

    Raises
    ------
    ProvenanceActorMismatchError
        When ``act.sub``/``act.cid`` do not match the auth token.
    """
    if provenance.act.sub != auth_token.sub:
        raise errors.ProvenanceActorMismatchError(
            "Provenance actor sub does not match the auth token subject"
        )
    if provenance.act.cid != auth_token.client_id:
        raise errors.ProvenanceActorMismatchError(
            "Provenance actor client_id does not match the auth token client_id"
        )


def verify_args(provenance: ProvenanceToken, args: Any) -> None:
    """Confirm the cleartext args match the token's args hash.

    Raises
    ------
    ProvenanceArgsMismatchError
        When the canonical hash of ``args`` does not equal ``ahs``.
    UnsupportedCanonicalizationError
        When ``aha`` names a canonicalization this verifier cannot reproduce.
    """
    if not provenance.verify_args(args):
        raise errors.ProvenanceArgsMismatchError(
            "Provenance args hash does not match the provided args"
        )


async def aauthenticate_provenance_header(
    headers: dict[str, str],
    settings: AuthentikateSettings | None = None,
) -> ProvenanceToken | None:
    """Extract and decode a provenance token from request headers.

    Returns None when no configured provenance header is present. Raises the
    usual provenance errors when a header is present but the token is invalid.
    """
    if not settings:
        settings = get_settings()

    raw = None
    for header_name in settings.provenance_header:
        raw = headers.get(header_name, None)
        if raw:
            break

    if not raw:
        return None

    return await adecode_provenance_token(raw, settings)


async def aauthenticate_provenance_header_or_none(
    headers: dict[str, str],
    settings: AuthentikateSettings | None = None,
) -> ProvenanceToken | None:
    """Like :func:`aauthenticate_provenance_header`, but never raises on a bad token.

    Returns the decoded token when present and valid, ``None`` when no provenance
    header is present, and ``None`` (after logging *why*) when a header is present
    but cannot be decoded/verified. Use this where a malformed or unverifiable
    provenance token should degrade gracefully rather than fail the request; the
    log records the reason so the failure is still observable.
    """
    try:
        return await aauthenticate_provenance_header(headers, settings)
    except (
        errors.JwtTokenError,
        errors.AuthentikateTokenExpired,
        errors.ProvenanceNotConfiguredError,
    ) as exc:
        logger.warning(
            "Could not decode provenance token from request headers (%s): %s",
            type(exc).__name__,
            exc,
            exc_info=True,
        )
        return None
