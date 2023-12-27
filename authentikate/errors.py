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
