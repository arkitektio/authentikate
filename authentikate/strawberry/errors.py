"""Turning authentikate's errors into coded GraphQL errors.

Strawberry surfaces an uncaught exception's ``str()`` as the message and nothing
else, so an expired token and a missing scope arrive indistinguishable on the
wire. Every failure raised from here instead carries::

    "extensions": {"code": "UNAUTHENTICATED", "reason": "TOKEN_EXPIRED"}

``code`` is kante's coarse category -- the branch a client acts on: refresh the
token, show "forbidden", or retry later. ``reason`` names the specific failure, so
a new one can be added without breaking a client that switches on ``code``.

This lives in the strawberry subpackage rather than in :mod:`authentikate.errors`
on purpose: the exception classes must stay importable by non-GraphQL callers
(``authenticate_header`` in a plain Django view), so the GraphQL dependency is
confined to the layer that actually needs it.

**What reaches the client.** Authorization failures name the requirement
("requires scope read:users") -- that is safe, because the ``Auth`` schema
directive already publishes ``required_scopes``/``required_roles`` into the
introspectable schema, so it discloses nothing new. Authentication failures use
the exception's ``client_message`` instead of ``str(exc)``, because the exception
message names the offending value -- the rejected issuer, audience or key id --
which is attacker-supplied. That detail is logged server-side instead.
"""

import logging
from typing import Any

from kante.errors import KanteError

from authentikate.errors import AuthentikateError, AuthentikatePermissionDenied

logger = logging.getLogger(__name__)

# --- reasons raised by the field directives rather than by an exception -------

NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
"""The field requires authentication and the request carried none."""

INSUFFICIENT_SCOPE = "INSUFFICIENT_SCOPE"
"""The token is valid but lacks a scope the field requires."""

INSUFFICIENT_ROLE = "INSUFFICIENT_ROLE"
"""The token is valid but lacks a role the field requires."""

INSUFFICIENT_ORGANIZATION_ROLE = "INSUFFICIENT_ORGANIZATION_ROLE"
"""The user lacks a role the field requires *within the active organization*."""


class AuthentikateGraphQLError(KanteError):
    """A GraphQL error carrying both a ``code`` and a ``reason``."""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        reason: str,
        **detail: Any,
    ) -> None:
        """Build the error, putting ``reason`` and any detail in the extensions."""
        extensions: dict[str, Any] = {"reason": reason}
        extensions.update(detail)
        super().__init__(message, code=code, extensions=extensions)


def denied(message: str, reason: str, **detail: Any) -> AuthentikateGraphQLError:
    """An authorization failure: authenticated, but not allowed.

    ``message`` may name the requirement -- the schema already publishes it.
    """
    from authentikate.errors import PERMISSION_DENIED

    return AuthentikateGraphQLError(
        message, code=PERMISSION_DENIED, reason=reason, **detail
    )


def unauthenticated(message: str, reason: str) -> AuthentikateGraphQLError:
    """An authentication failure: no usable credentials."""
    from authentikate.errors import UNAUTHENTICATED

    return AuthentikateGraphQLError(message, code=UNAUTHENTICATED, reason=reason)


def to_graphql_error(
    exc: AuthentikateError | AuthentikatePermissionDenied,
) -> AuthentikateGraphQLError:
    """Translate an authentikate exception into a coded GraphQL error.

    The client gets ``exc.client_message``; the original -- which names the
    rejected issuer, audience or key id -- goes to the log instead, so the error
    surface cannot be used to probe what this service trusts.
    """
    logger.warning(
        "Authentication/authorization failed (%s/%s): %s",
        exc.code,
        exc.reason,
        exc,
        exc_info=True,
    )

    return AuthentikateGraphQLError(
        exc.client_message, code=exc.code, reason=exc.reason
    )


__all__ = [
    "AuthentikateGraphQLError",
    "INSUFFICIENT_ORGANIZATION_ROLE",
    "INSUFFICIENT_ROLE",
    "INSUFFICIENT_SCOPE",
    "NOT_AUTHENTICATED",
    "denied",
    "to_graphql_error",
    "unauthenticated",
]
