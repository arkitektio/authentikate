"""Whether, and how, this service serves a scoped member.

A scoped member's token (:attr:`JWTToken.is_scoped`) names the organization like
any other, but its holder was shared a few objects and nothing else. Every read
of such a request has to be narrowed to those objects -- and authentikate does
not know a service's objects. So a scoped token is only accepted where something
that does has said it narrows them::

    from authentikate.scoped import enforce_scoped

    enforce_scoped(hub_resolver=lambda: "3")  # e.g. arkitekt-service, once a structure has reaches

Until then (``SCOPED_TOKENS: auto``, the default) a scoped token is rejected with
``SCOPED_TOKEN_UNSUPPORTED`` at :func:`authentikate.utils.authenticate_token`,
which every transport goes through: a service that never wired sharing shuts
scoped members out rather than handing them the organization.

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

from authentikate.base_models import AuthentikateSettings, JWTToken
from authentikate.errors import FullMembershipRequired, ScopedTokenUnsupported

ScopedMode = Literal["enforce", "reject", "self"]
"""What a scoped token meets here, once ``auto`` is resolved."""

HubResolver = Callable[[], "str | None"]

_enforcer: "list[HubResolver | None]" = []


def enforce_scoped(hub_resolver: HubResolver | None = None) -> None:
    """Declare that this process narrows every read to a scoped member's objects.

    Called by whatever does the narrowing, when it is set up. ``hub_resolver``
    names this service's hub when the ``HUB`` setting does not; it is called on
    the request path, so it must answer from memory, never from the network.
    """
    _enforcer[:] = [hub_resolver]


def stop_enforcing() -> None:
    """Undo :func:`enforce_scoped` (tests)."""
    _enforcer.clear()


def is_enforced() -> bool:
    """Whether something in this process narrows reads to a scoped member's objects."""
    return bool(_enforcer)


def current_hub(settings: AuthentikateSettings) -> str | None:
    """This service's hub, whose entry of a scoped token's ``objects`` it reads."""
    if settings.hub is not None:
        return settings.hub
    resolver = _enforcer[0] if _enforcer else None
    return resolver() if resolver is not None else None


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
    if mode == "enforce" and current_hub(settings) is None:
        raise ScopedTokenUnsupported(
            "This service narrows scoped members but does not know its hub (set AUTHENTIKATE.HUB)"
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
        raise FullMembershipRequired(f"{token.sub} is a scoped member")
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
    "HubResolver",
    "ScopedMode",
    "check_scoped_token",
    "current_hub",
    "enforce_scoped",
    "full_members_only",
    "is_enforced",
    "require_full_member",
    "scoped_mode",
    "stop_enforcing",
]
