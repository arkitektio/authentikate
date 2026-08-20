"""The error model, and the codes each error reports to a client.

Every error carries three class attributes:

``code``
    The coarse, machine-readable category, mirroring ``kante.errors``:
    ``UNAUTHENTICATED``, ``PERMISSION_DENIED`` or ``INTERNAL_ERROR``. This is the
    branch a client actually acts on -- refresh the token, show "forbidden", or
    retry later.
``reason``
    The specific failure within that category (``TOKEN_EXPIRED``,
    ``INSUFFICIENT_SCOPE``, ...). Adding a new one is not a breaking change for a
    client that switches on ``code``.
``client_message``
    The message that reaches the client. Deliberately *not* ``str(exc)``: the
    exception message names the offending value (the rejected issuer, audience or
    key id), which is attacker-supplied on the authentication path. That detail
    belongs in the server log, not in the response.

The attributes are plain strings, so this module stays free of any GraphQL
import: these are ``django.core.exceptions.PermissionDenied`` subclasses and must
keep rendering as a 403 for the non-GraphQL callers documented in the README. The
translation into a coded GraphQL error lives in
:mod:`authentikate.strawberry.errors`.
"""

from django.core.exceptions import PermissionDenied

UNAUTHENTICATED = "UNAUTHENTICATED"
"""No usable credentials were presented; the client should refresh or log in."""

PERMISSION_DENIED = "PERMISSION_DENIED"
"""The request is authenticated but not allowed to do this."""

INTERNAL_ERROR = "INTERNAL_ERROR"
"""A server-side fault, not a decision about the caller's credentials."""


class AuthentikateError(Exception):
    """Base class for all authentikate errors that are
    not permission related. Inherits from Exception"""

    code: str = INTERNAL_ERROR
    reason: str = "INTERNAL_ERROR"
    client_message: str = "An internal error occurred."


class AuthentikatePermissionDenied(PermissionDenied):
    """Base class for all authentikate permission errors. Inherits from
    django.core.exceptions.PermissionDenied"""

    code: str = PERMISSION_DENIED
    reason: str = "PERMISSION_DENIED"
    client_message: str = "You are not allowed to perform this action."


class AuthentikateTokenExpired(AuthentikatePermissionDenied):
    """Raised when a token is expired"""

    code = UNAUTHENTICATED
    reason = "TOKEN_EXPIRED"
    client_message = "The access token has expired."


class JwtTokenError(AuthentikatePermissionDenied):
    """Base class for all JWT token errors"""

    code = UNAUTHENTICATED
    reason = "TOKEN_INVALID"
    client_message = "The access token could not be verified."


class MalformedJwtTokenError(JwtTokenError):
    """Raised when a token is malformed."""

    reason = "TOKEN_MALFORMED"
    client_message = "The access token is malformed."


class InvalidJwtTokenError(JwtTokenError):
    """Raised when a token is invalid."""

    reason = "TOKEN_INVALID"
    client_message = "The access token could not be verified."


class AuthentikateUserNotFound(AuthentikatePermissionDenied):
    """Raised when a user is not found"""

    code = UNAUTHENTICATED
    reason = "USER_NOT_FOUND"
    client_message = "No user matches these credentials."


class NoAuthorizationHeader(AuthentikatePermissionDenied):
    """Raised when no authorization header is found in the headers"""

    code = UNAUTHENTICATED
    reason = "NO_AUTHORIZATION_HEADER"
    client_message = "No Authorization header was provided."


class MalformedAuthorizationHeader(AuthentikatePermissionDenied):
    """Raised when the authorization header is malformed (e.g. not Bearer)"""

    code = UNAUTHENTICATED
    reason = "MALFORMED_AUTHORIZATION_HEADER"
    client_message = "The Authorization header is not a valid Bearer token."


class MissingActiveOrganization(AuthentikatePermissionDenied):
    """Raised when an authenticated token does not provide an active organization."""

    reason = "MISSING_ACTIVE_ORGANIZATION"
    client_message = "The token does not name an active organization."


class OrganizationNotAllowed(AuthentikatePermissionDenied):
    """Raised when a token names an organization this service does not accept."""

    reason = "ORGANIZATION_NOT_ALLOWED"
    client_message = "This service does not accept the organization in your token."


class BlockedMembership(AuthentikatePermissionDenied):
    """Raised when the resolved membership is blocked."""

    reason = "MEMBERSHIP_BLOCKED"
    client_message = "Your membership in this organization is blocked."


class JwksError(AuthentikateError):
    """Raised when there is an error with the JWKS"""

    # Not a permission decision: the issuer is unreachable or its JWKS is
    # unusable. Reporting it as a denial would tell the client to re-authenticate
    # against a problem no credential can fix.
    code = INTERNAL_ERROR
    reason = "KEY_RETRIEVAL_FAILED"
    client_message = "The signing keys could not be retrieved. Try again later."


class KeyNotFoundError(AuthentikatePermissionDenied):
    """Raised when the key is not found in the JWKS"""

    code = UNAUTHENTICATED
    reason = "SIGNING_KEY_NOT_FOUND"
    client_message = "The token was signed with an unknown key."


class ProvenanceTokenError(JwtTokenError):
    """Base class for all provenance token errors."""

    # Provenance is an authorization concern: the auth token is fine, the
    # attestation travelling with it is not.
    code = PERMISSION_DENIED
    reason = "PROVENANCE_INVALID"
    client_message = "The provenance token could not be verified."


class MalformedProvenanceTokenError(ProvenanceTokenError):
    """Raised when a provenance token payload is malformed."""

    reason = "PROVENANCE_MALFORMED"
    client_message = "The provenance token is malformed."


class InvalidProvenanceTokenError(ProvenanceTokenError):
    """Raised when a provenance token signature or claims are invalid."""

    reason = "PROVENANCE_INVALID"


class ProvenanceAudienceError(ProvenanceTokenError):
    """Raised when the configured service is not in the token's audience."""

    reason = "PROVENANCE_AUDIENCE_MISMATCH"
    client_message = "The provenance token is not scoped to this service."


class ProvenanceActorMismatchError(ProvenanceTokenError):
    """Raised when the token's actor does not match the presenting auth token."""

    reason = "PROVENANCE_ACTOR_MISMATCH"
    client_message = (
        "The provenance token was issued to a different actor than the one "
        "presenting it."
    )


class ProvenanceArgsMismatchError(ProvenanceTokenError):
    """Raised when the cleartext args do not match the token's args hash."""

    reason = "PROVENANCE_ARGS_MISMATCH"
    client_message = "The provided args do not match the provenance token."


class ProvenanceValidationError(ProvenanceTokenError):
    """Raised when a provenance token is present on a request but fails validation.

    The graceful ``*_or_none`` path swallows an unverifiable provenance token and
    lets the request proceed as if none were supplied. This error is raised in the
    opposite, fail-closed case: once a request actually carries a provenance
    token, that token must validate — otherwise the request is rejected rather
    than silently treated as unprovenanced. The specific underlying failure
    (signature, expiry, audience, malformed payload, missing configuration) is
    chained as the cause.
    """

    reason = "PROVENANCE_INVALID"


class ProvenanceNotConfiguredError(AuthentikateError):
    """Raised when provenance verification is attempted without configuration."""

    code = INTERNAL_ERROR
    reason = "PROVENANCE_NOT_CONFIGURED"
    client_message = "Provenance verification is not configured on this service."


class UnsupportedCanonicalizationError(AuthentikateError):
    """Raised when an args-hash canonicalization version is not supported."""

    code = INTERNAL_ERROR
    reason = "UNSUPPORTED_CANONICALIZATION"
    client_message = (
        "The provenance token uses an args canonicalization this service cannot "
        "reproduce."
    )
