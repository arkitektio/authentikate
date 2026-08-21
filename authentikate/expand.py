import hashlib
import re
from dataclasses import dataclass
from django.db import IntegrityError
from authentikate import base_models, models
import logging
from typing import cast
from authentikate.errors import BlockedMembership, MissingActiveOrganization
from authentikate.protocols import (
    UserModel,
    OrganizationModel,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ExpandedTokenContext:
    """Expanded models derived from a single authenticated token."""

    user: models.User
    client: models.Client
    organization: models.Organization
    membership: models.Membership


async def aresolve_client_relations(
    token: base_models.JWTToken,
) -> tuple[models.Release | None, models.Device | None]:
    """Resolve related models referenced by a client token."""
    release = None
    device = None

    if token.client_app and token.client_release:
        app, _ = await models.App.objects.aget_or_create(identifier=token.client_app)
        release, _ = await models.Release.objects.aget_or_create(
            app=app, version=token.client_release
        )

    if token.client_device:
        device, _ = await models.Device.objects.aget_or_create(
            device_id=token.client_device
        )

    return release, device


def resolve_client_relations(
    token: base_models.JWTToken,
) -> tuple[models.Release | None, models.Device | None]:
    """Resolve related models referenced by a client token."""
    release = None
    device = None

    if token.client_app and token.client_release:
        app, _ = models.App.objects.get_or_create(identifier=token.client_app)
        release, _ = models.Release.objects.get_or_create(
            app=app, version=token.client_release
        )

    if token.client_device:
        device, _ = models.Device.objects.get_or_create(device_id=token.client_device)

    return release, device


USERNAME_MAX_LENGTH = 150
"""Mirrors ``AbstractUser.username``'s ``max_length``."""

_USERNAME_DIGEST_LENGTH = 12

_DISALLOWED_IN_USERNAME = re.compile(r"[^\w.@+-]", re.UNICODE)
"""The complement of the charset ``UnicodeUsernameValidator`` accepts."""


def token_to_username(token: base_models.JWTToken) -> str:
    """Derive a Django-valid username from a token's ``iss`` and ``sub``.

    The username is only a display and uniqueness artifact -- users are looked
    up by ``(sub, iss)`` -- but it still has to satisfy the constraints Django
    puts on the field, which the naive ``f"{iss}_{sub}"`` did not:

    - ``UnicodeUsernameValidator`` allows only ``[\\w.@+-]``, and issuer URLs
      contain ``:`` and ``/``. ``save()`` does not run validators so the bad
      value persisted silently, but ``full_clean()`` -- and therefore the Django
      admin -- rejected it, leaving token-provisioned users uneditable.
    - ``max_length`` is 150, which a long issuer URL plus a long ``sub`` can
      exceed. SQLite truncates silently; PostgreSQL raises ``DataError``.

    So: replace every disallowed character, then always append a short digest of
    the *original* ``iss``/``sub`` pair, truncating the readable part to fit.
    The digest is unconditional rather than only-on-overflow because the
    replacement is lossy -- ``https://a.example`` and ``https-//a.example``
    sanitize identically -- and ``username`` is ``unique=True``, so a collision
    would turn provisioning into an ``IntegrityError``, i.e. a login outage for
    whichever user came second.

    Parameters
    ----------
    token : base_models.JWTToken
        The token to convert

    Returns
    -------
    str
        A username that is stable for a given ``(iss, sub)``, valid per Django's
        username validator, and no longer than 150 characters.
    """
    # A separator that cannot appear in either part, so the digest is always
    # distinguishable from the readable prefix.
    digest = hashlib.sha256(
        "\0".join([token.iss, token.sub]).encode("utf-8")
    ).hexdigest()[:_USERNAME_DIGEST_LENGTH]

    readable = _DISALLOWED_IN_USERNAME.sub("-", f"{token.iss}_{token.sub}")
    room = USERNAME_MAX_LENGTH - len(digest) - 1
    return f"{readable[:room]}-{digest}"


async def aexpand_organization_from_token(
    token: base_models.JWTToken,
) -> models.Organization:
    """
    Expand an organization from the provided JWT token.
    """
    if not token.org:
        raise MissingActiveOrganization("Token does not contain an active organization")

    org, _ = await models.Organization.objects.aget_or_create(slug=token.org)
    return org


async def aexpand_membership(
    user: UserModel, organization: OrganizationModel, token: base_models.JWTToken
) -> models.Membership:
    """
    Expand a membership from the provided user and organization.


    """
    membership, _ = await models.Membership.objects.aupdate_or_create(
        user_id=user.id,
        organization_id=organization.id,
        defaults=dict(
            roles=token.roles,
        ),
    )
    if membership.blocked:
        raise BlockedMembership("Membership is blocked")
    return membership


def expand_organization_from_token(
    token: base_models.JWTToken,
) -> models.Organization:
    """
    Expand an organization from the provided JWT token.
    """
    if not token.org:
        raise MissingActiveOrganization("Token does not contain an active organization")

    org, _ = models.Organization.objects.get_or_create(slug=token.org)
    return org


def expand_membership(
    user: UserModel, organization: OrganizationModel, token: base_models.JWTToken
) -> models.Membership:
    """
    Expand a membership from the provided user and organization.

    Note that deleting a membership does not revoke access: it is recreated from
    the token on the next request. ``blocked=True`` is the supported revocation.
    """
    membership, _ = models.Membership.objects.update_or_create(
        user_id=user.id,
        organization_id=organization.id,
        defaults=dict(
            roles=token.roles,
        ),
    )
    if membership.blocked:
        raise BlockedMembership("Membership is blocked")
    return membership


async def _aexpand_user(
    token: base_models.JWTToken,
    organization: models.Organization | None = None,
) -> models.User:
    """Get or create the user a token refers to, without authorizing them.

    Low-level: it deliberately performs no membership or blocked check. Callers
    that authenticate a request must go through :func:`aexpand_token_context`
    (or :func:`aexpand_user_from_token`) instead.
    """

    try:
        user = await models.User.objects.aget(sub=token.sub, iss=token.iss)
    except models.User.DoesNotExist:
        user = models.User(
            sub=token.sub,
            username=token_to_username(token),
            iss=token.iss,
        )
        user.set_unusable_password()
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash

        if organization is not None:
            user.active_organization = organization
        elif token.org:
            current_org, _ = await models.Organization.objects.aget_or_create(
                slug=token.org,
            )
            user.active_organization = current_org

        try:
            await user.asave()
            return user
        except IntegrityError:
            # Lost a concurrent create race: another request authenticating the
            # same token already inserted this (sub, iss) user. Fall through to
            # treat the winner's row as an existing user instead of propagating
            # the IntegrityError.
            user = await models.User.objects.aget(sub=token.sub, iss=token.iss)

    if user.changed_hash != token.changed_hash:
        # The token's user metadata changed since we last saw it: sync it across.
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash

        if organization is not None:
            user.active_organization = organization
        elif token.org:
            current_org, _ = await models.Organization.objects.aget_or_create(
                slug=token.org,
            )
            user.active_organization = current_org

        await user.asave()

    return user


async def aexpand_token_context(
    token: base_models.JWTToken,
) -> ExpandedTokenContext:
    """Expand all request-scoped auth models for a token in one code path."""

    organization = await aexpand_organization_from_token(token)
    user = await _aexpand_user(token, organization=organization)
    client = await aexpand_client_from_token(token)
    membership = await aexpand_membership(
        cast(UserModel, user),
        cast(OrganizationModel, organization),
        token,
    )

    return ExpandedTokenContext(
        user=user,
        client=client,
        organization=organization,
        membership=membership,
    )


async def aexpand_user_from_token(
    token: base_models.JWTToken,
) -> models.User:
    """
    Expand a user from the provided JWT token.

    Resolves the organization and membership too, so a blocked membership is
    rejected here exactly as it is on the sync path.
    """

    return (await aexpand_token_context(token)).user


def _expand_user(
    token: base_models.JWTToken,
    organization: models.Organization | None = None,
) -> models.User:
    """Get or create the user a token refers to, without authorizing them.

    Low-level: it deliberately performs no membership or blocked check. Callers
    that authenticate a request must go through :func:`expand_token_context`
    (or :func:`expand_user_from_token`) instead.
    """

    try:
        user = models.User.objects.get(sub=token.sub, iss=token.iss)
    except models.User.DoesNotExist:
        user = models.User(
            sub=token.sub,
            username=token_to_username(token),
            iss=token.iss,
        )
        user.set_unusable_password()
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash

        if organization is not None:
            user.active_organization = organization
        elif token.org:
            current_org, _ = models.Organization.objects.get_or_create(
                slug=token.org
            )
            user.active_organization = current_org

        try:
            user.save()
            return user
        except IntegrityError:
            # Lost a concurrent create race: another request authenticating the
            # same token already inserted this (sub, iss) user. Fall through to
            # treat the winner's row as an existing user instead of propagating
            # the IntegrityError.
            user = models.User.objects.get(sub=token.sub, iss=token.iss)

    if user.changed_hash != token.changed_hash:
        # The token's user metadata changed since we last saw it: sync it across.
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash

        if organization is not None:
            user.active_organization = organization
        elif token.org:
            current_org, _ = models.Organization.objects.get_or_create(
                slug=token.org
            )
            user.active_organization = current_org

        user.save()

    return user


def expand_token_context(
    token: base_models.JWTToken,
) -> ExpandedTokenContext:
    """Expand all request-scoped auth models for a token in one code path.

    The blocking twin of :func:`aexpand_token_context`, kept deliberately
    identical: a blocked membership must fail the same way on both.
    """

    organization = expand_organization_from_token(token)
    user = _expand_user(token, organization=organization)
    client = expand_client_from_token(token)
    membership = expand_membership(
        cast(UserModel, user),
        cast(OrganizationModel, organization),
        token,
    )

    return ExpandedTokenContext(
        user=user,
        client=client,
        organization=organization,
        membership=membership,
    )


def expand_user_from_token(
    token: base_models.JWTToken,
) -> models.User:
    """
    Expand a user from the provided JWT token.

    Resolves the organization and membership too, so a blocked membership is
    rejected here exactly as it is on the async path.
    """

    return expand_token_context(token).user


async def aexpand_client_from_token(
    token: base_models.JWTToken,
) -> models.Client:
    """
    Expand a client from the provided JWT token.
    """
    release, device = await aresolve_client_relations(token)
    client, _ = await models.Client.objects.aget_or_create(
        client_id=token.client_id,
        iss=token.iss,
        defaults={"release": release, "device": device},
    )

    if getattr(client, "device_id", None) is None and device:
        client.device = device
        await client.asave(update_fields=["device"])

    if getattr(client, "release_id", None) is None and release:
        client.release = release
        await client.asave(update_fields=["release"])

    return client


def expand_client_from_token(
    token: base_models.JWTToken,
) -> models.Client:
    """
    Expand a client from the provided JWT token.
    """
    release, device = resolve_client_relations(token)
    client, _ = models.Client.objects.get_or_create(
        client_id=token.client_id,
        iss=token.iss,
        defaults={"release": release, "device": device},
    )

    if not client.device and device:
        client.device = device
        client.save(update_fields=["device"])

    if not client.release and release:
        client.release = release
        client.save(update_fields=["release"])

    return client
