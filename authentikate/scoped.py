"""Whether, and how, this service serves a guest.

A guest's token (:attr:`JWTToken.is_scoped`) names the organization like any
other, but its holder was granted a few *collaborations* and nothing else, with roles that
hold only inside each (``collabs``). Every read of such a request has to be held to
what is in those collaborations -- and authentikate does not know a service's collaborations. So
a guest's token is only accepted where something that does has said it holds them
there::

    from authentikate.scoped import enforce_scoped

    enforce_scoped()  # e.g. arkitekt-service, for a schema behind its collaboration gate

A guest's collaborations are read for this service instance: its ``audience``, which names it
(a service whose audience is ``*`` serves no guests).

Until then (``SCOPED_TOKENS: auto``, the default) a guest's token is rejected with
``SCOPED_TOKEN_UNSUPPORTED`` at :func:`authentikate.utils.authenticate_token`,
which every transport goes through: a service that never wired collaborations shuts
guests out rather than handing them the organization.

Where it is accepted, it is read-only: the GraphQL extension rejects its
mutations and subscriptions (``SCOPED_READ_ONLY``) unless every root field opted
in (``AuthExtension(allow_scoped=True)``), and outside GraphQL
:func:`require_full_member` / :func:`full_members_only` refuse it.

``SCOPED_TOKENS: self`` accepts it without either gate, for a service that
applies its own rules to scoped members (lok). ``reject`` always rejects it.
"""

import asyncio
import functools
from typing import Any, Callable, Literal

from authentikate.base_models import ANY_AUDIENCE, AuthentikateSettings, JWTToken
from authentikate.errors import FullMembershipRequired, ScopedTokenUnsupported

ScopedMode = Literal["enforce", "reject", "self"]
"""What a scoped token meets here, once ``auto`` is resolved."""

_enforced: list[bool] = []


def enforce_scoped() -> None:
    """Declare that this process holds every read of a guest to their collaborations.

    Called by whatever does that, when it is set up.
    """
    _enforced[:] = [True]


def stop_enforcing() -> None:
    """Undo :func:`enforce_scoped` (tests)."""
    _enforced.clear()


def is_enforced() -> bool:
    """Whether something in this process holds a guest's reads to their collaborations."""
    return bool(_enforced)


def current_instance(settings: AuthentikateSettings) -> str | None:
    """This service instance, whose entry of a guest's ``collabs`` it reads: its ``audience``,
    unless that is ``*`` (any audience names no instance)."""
    return settings.audience if settings.audience != ANY_AUDIENCE else None


def scoped_mode(settings: AuthentikateSettings) -> ScopedMode:
    """``SCOPED_TOKENS`` with ``auto`` resolved: enforce where narrowed, reject elsewhere."""
    if settings.scoped_tokens == "auto":
        return "enforce" if is_enforced() else "reject"
    return settings.scoped_tokens


def check_scoped_token(token: JWTToken, settings: AuthentikateSettings) -> None:
    """Reject a scoped token this service cannot serve; a full member's always passes."""
    if not token.is_scoped:
        return
    mode = scoped_mode(settings)
    if mode == "reject":
        raise ScopedTokenUnsupported("This service does not serve scoped members")
    if mode == "enforce" and current_instance(settings) is None:
        raise ScopedTokenUnsupported(
            "This service serves guests but its audience names no instance (it is *)"
        )


def require_full_member(token: JWTToken | None = None) -> JWTToken:
    """The request's token, unless it is a scoped member's (``FULL_MEMBERSHIP_REQUIRED``).

    For code outside GraphQL that only makes sense for someone acting for the
    organization: uploads, credentials, administration. ``token`` defaults to
    the one the request was authenticated with (:func:`authentikate.vars.get_token`).
    """
    if token is None:
        from authentikate.vars import get_token

        token = get_token()
    if token is None:
        raise FullMembershipRequired("No authenticated token")
    if token.is_scoped:
        raise FullMembershipRequired(f"{token.sub} is a guest")
    return token


def full_members_only(view: Callable[..., Any]) -> Callable[..., Any]:
    """Decorate a Django view: authenticate its bearer token and refuse a scoped member's.

    The view runs with the token set (:func:`authentikate.vars.get_token`). A
    refusal is an :class:`~authentikate.errors.AuthentikatePermissionDenied`,
    which Django renders as a 403.
    """
    from asgiref.sync import sync_to_async

    from authentikate.settings import get_settings
    from authentikate.utils import authenticate_header

    call = view if asyncio.iscoroutinefunction(view) else sync_to_async(view)

    @functools.wraps(view)
    async def wrapper(request: Any, *args: Any, **kwargs: Any) -> Any:
        from authentikate.vars import token_var

        token = require_full_member(await authenticate_header(dict(request.headers), get_settings()))
        reset = token_var.set(token)
        try:
            return await call(request, *args, **kwargs)
        finally:
            token_var.reset(reset)

    return wrapper


__all__ = [
    "ScopedMode",
    "check_scoped_token",
    "current_instance",
    "enforce_scoped",
    "full_members_only",
    "is_enforced",
    "require_full_member",
    "scoped_mode",
    "stop_enforcing",
]
