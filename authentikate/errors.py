from django.core.exceptions import PermissionDenied


class AuthentikateError(Exception):
    """Base class for all authentikate errors that are
    not permission related. Inherits from Exception"""

    pass


class AuthentikatePermissionDenied(PermissionDenied):
    """Base class for all authentikate permission errors. Inherits from
    django.core.exceptions.PermissionDenied"""

    pass


class AuthentikateTokenExpired(AuthentikatePermissionDenied):
    """Raised when a token is expired"""

    pass


class JwtTokenError(AuthentikatePermissionDenied):
    """Base class for all JWT token errors"""

    pass


class MalformedJwtTokenError(JwtTokenError):
    """Raised when a token is malformed."""

    pass


class InvalidJwtTokenError(JwtTokenError):
    """Raised when a token is invalid."""

    pass


class AuthentikateUserNotFound(AuthentikatePermissionDenied):
    """Raised when a user is not found"""

    pass


class NoAuthorizationHeader(AuthentikatePermissionDenied):
    """Raised when no authorization header is found in the headers"""

    pass


class MalformedAuthorizationHeader(AuthentikatePermissionDenied):
    """Raised when the authorization header is malformed (e.g. not Bearer)"""

    pass


class InvalidTaskAssignment(AuthentikatePermissionDenied):
    """Raised when a Rekuest task is assigned outside the authenticated org."""

    pass


class MissingActiveOrganization(AuthentikatePermissionDenied):
    """Raised when an authenticated token does not provide an active organization."""

    pass


class BlockedMembership(AuthentikatePermissionDenied):
    """Raised when the resolved membership is blocked."""

    pass


class JwksError(AuthentikateError):
    """Raised when there is an error with the JWKS"""

    pass


class KeyNotFoundError(AuthentikatePermissionDenied):
    """Raised when the key is not found in the JWKS"""

    pass


class ProvenanceTokenError(JwtTokenError):
    """Base class for all provenance token errors."""

    pass


class MalformedProvenanceTokenError(ProvenanceTokenError):
    """Raised when a provenance token payload is malformed."""

    pass


class InvalidProvenanceTokenError(ProvenanceTokenError):
    """Raised when a provenance token signature or claims are invalid."""

    pass


class ProvenanceAudienceError(ProvenanceTokenError):
    """Raised when the configured service is not in the token's audience."""

    pass


class ProvenanceActorMismatchError(ProvenanceTokenError):
    """Raised when the token's actor does not match the presenting auth token."""

    pass


class ProvenanceArgsMismatchError(ProvenanceTokenError):
    """Raised when the cleartext args do not match the token's args hash."""

    pass


class ProvenanceNotConfiguredError(AuthentikateError):
    """Raised when provenance verification is attempted without configuration."""

    pass


class UnsupportedCanonicalizationError(AuthentikateError):
    """Raised when an args-hash canonicalization version is not supported."""

    pass
