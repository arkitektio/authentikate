"""Authentikate is a simple token based authentication library for Python

Authentikate is a simple token based authentication library for Python. It
provides convenient functions to authenticate requests and decode tokens,
authenticating users and applications.

It is designed to be used with Django, but can be used with any Python
framework.

Supported Token Types
- JWT (JSON Web Tokens) (with client_id, user_id, scopes, and expiration)
- Static tokens (for testing and pre-defined tokens)
- Provenance tokens (Ed25519-signed attestations minted by Rekuest, verified on
  the consuming/audience end via :mod:`authentikate.provenance`)

The names below are the public API and can be imported straight from
``authentikate``::

    from authentikate import authenticate_header, JWTToken

Everything else is an implementation detail and may move between releases.
"""

import importlib
from typing import TYPE_CHECKING, Any

# --- IMPORTANT: these imports are lazy on purpose. -------------------------
#
# ``authentikate`` is a Django app, so Django imports this module while
# populating INSTALLED_APPS -- *before* the app registry is ready. Several of
# the names below live in modules that import ``authentikate.models``, and
# importing a model that early raises:
#
#     AppRegistryNotReady: Apps aren't loaded yet.
#
# which would break startup for every project using this library. Resolving the
# names in ``__getattr__`` (PEP 562) defers each import to first use, by which
# time the registry is populated. The ``TYPE_CHECKING`` block below gives type
# checkers and IDEs the same names statically, at no runtime cost.
#
# Do not convert these into ordinary module-level imports.
# ---------------------------------------------------------------------------

if TYPE_CHECKING:
    from authentikate.base_models import (
        AuthentikateSettings,
        JWTToken,
        StaticToken,
    )
    from authentikate.decode import adecode_token, decode_token
    from authentikate.errors import (
        AuthentikateError,
        AuthentikatePermissionDenied,
        AuthentikateTokenExpired,
        BlockedMembership,
        InvalidJwtTokenError,
        JwksError,
        JwtTokenError,
        MalformedAuthorizationHeader,
        MalformedJwtTokenError,
        MissingActiveOrganization,
        NoAuthorizationHeader,
        OrganizationNotAllowed,
    )
    from authentikate.expand import (
        ExpandedTokenContext,
        aexpand_token_context,
        expand_token_context,
    )
    from authentikate.settings import get_settings
    from authentikate.utils import (
        authenticate_header,
        authenticate_header_or_none,
        authenticate_token,
        authenticate_token_or_none,
    )
    from authentikate.vars import (
        get_client,
        get_membership,
        get_organization,
        get_token,
        get_user,
    )


_EXPORTS: dict[str, str] = {
    # settings
    "AuthentikateSettings": "authentikate.base_models",
    "get_settings": "authentikate.settings",
    # tokens
    "JWTToken": "authentikate.base_models",
    "StaticToken": "authentikate.base_models",
    # authenticating a request
    "authenticate_header": "authentikate.utils",
    "authenticate_header_or_none": "authentikate.utils",
    "authenticate_token": "authentikate.utils",
    "authenticate_token_or_none": "authentikate.utils",
    # decoding a raw token
    "decode_token": "authentikate.decode",
    "adecode_token": "authentikate.decode",
    # materialising a token into Django models
    "ExpandedTokenContext": "authentikate.expand",
    "expand_token_context": "authentikate.expand",
    "aexpand_token_context": "authentikate.expand",
    # the current principal, within a request
    "get_token": "authentikate.vars",
    "get_user": "authentikate.vars",
    "get_client": "authentikate.vars",
    "get_organization": "authentikate.vars",
    "get_membership": "authentikate.vars",
    # errors worth catching by name
    "AuthentikateError": "authentikate.errors",
    "AuthentikatePermissionDenied": "authentikate.errors",
    "AuthentikateTokenExpired": "authentikate.errors",
    "JwtTokenError": "authentikate.errors",
    "InvalidJwtTokenError": "authentikate.errors",
    "MalformedJwtTokenError": "authentikate.errors",
    "NoAuthorizationHeader": "authentikate.errors",
    "MalformedAuthorizationHeader": "authentikate.errors",
    "MissingActiveOrganization": "authentikate.errors",
    "OrganizationNotAllowed": "authentikate.errors",
    "BlockedMembership": "authentikate.errors",
    "JwksError": "authentikate.errors",
}

__all__ = [
    "AuthentikateError",
    "AuthentikatePermissionDenied",
    "AuthentikateSettings",
    "AuthentikateTokenExpired",
    "BlockedMembership",
    "ExpandedTokenContext",
    "InvalidJwtTokenError",
    "JWTToken",
    "JwksError",
    "JwtTokenError",
    "MalformedAuthorizationHeader",
    "MalformedJwtTokenError",
    "MissingActiveOrganization",
    "NoAuthorizationHeader",
    "OrganizationNotAllowed",
    "StaticToken",
    "adecode_token",
    "aexpand_token_context",
    "authenticate_header",
    "authenticate_header_or_none",
    "authenticate_token",
    "authenticate_token_or_none",
    "decode_token",
    "expand_token_context",
    "get_client",
    "get_membership",
    "get_organization",
    "get_settings",
    "get_token",
    "get_user",
]


def __getattr__(name: str) -> Any:
    """Resolve a public name to its defining module on first access (PEP 562)."""
    try:
        module = _EXPORTS[name]
    except KeyError:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}"
        ) from None

    return getattr(importlib.import_module(module), name)


def __dir__() -> list[str]:
    """List the public names alongside whatever is already in the namespace."""
    return sorted({*globals(), *_EXPORTS})
