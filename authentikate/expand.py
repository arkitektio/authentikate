from dataclasses import dataclass
from django.contrib.auth.models import Group
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


def token_to_username(token: base_models.JWTToken) -> str:
    """Convert a JWT token to a username

    Parameters
    ----------
    token : structs.JWTToken
        The token to convert

    Returns
    -------

    str
        The username



    """
    # Generate a username based on the token's iss and sub
    # and ensure it's unique
    return f"{token.iss}_{token.sub}"


async def aset_user_groups(user: models.User, roles: list[str]) -> None:
    """Sync a user's groups with a list of roles

    Roles are mirrored as groups: groups for roles no longer present
    are removed from the user.

    Parameters
    ----------
    user : models.User
        The user to sync the roles on
    roles : list[str]
        The roles to sync
    """
    groups = []
    for role in roles:
        g, _ = await Group.objects.aget_or_create(name=role)
        groups.append(g)
    await user.groups.aset(groups)


def set_user_groups(user: models.User, roles: list[str]) -> None:
    """Sync a user's groups with a list of roles

    Roles are mirrored as groups: groups for roles no longer present
    are removed from the user.

    Parameters
    ----------
    user : models.User
        The user to sync the roles on
    roles : list[str]
        The roles to sync
    """
    groups = []
    for role in roles:
        g, _ = Group.objects.get_or_create(name=role)
        groups.append(g)
    user.groups.set(groups)


async def aexpand_organization_from_token(
    token: base_models.JWTToken,
) -> models.Organization:
    """
    Expand an organization from the provided JWT token.
    """
    if not token.active_org:
        raise MissingActiveOrganization("Token does not contain an active organization")

    org, _ = await models.Organization.objects.aget_or_create(slug=token.active_org)
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


async def aexpand_user_from_token(
    token: base_models.JWTToken,
    organization: models.Organization | None = None,
) -> models.User:
    """
    Expand a user from the provided JWT token.
    """

    try:
        user = await models.User.objects.aget(sub=token.sub, iss=token.iss)
        if user.changed_hash != token.changed_hash:
            # User has changed, update the user object
            user.first_name = token.preferred_username
            user.changed_hash = token.changed_hash

            if organization is not None:
                user.active_organization = organization
            elif token.active_org:
                current_org, _ = await models.Organization.objects.aget_or_create(
                    slug=token.active_org,
                )
                user.active_organization = current_org

            await user.asave()
            await aset_user_groups(user, token.roles)

        return user

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
        elif token.active_org:
            current_org, _ = await models.Organization.objects.aget_or_create(
                slug=token.active_org,
            )
            user.active_organization = current_org

        await user.asave()
        await aset_user_groups(user, token.roles)
        return user


async def aexpand_token_context(
    token: base_models.JWTToken,
) -> ExpandedTokenContext:
    """Expand all request-scoped auth models for a token in one code path."""

    organization = await aexpand_organization_from_token(token)
    user = await aexpand_user_from_token(token, organization=organization)
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


def expand_user_from_token(
    token: base_models.JWTToken,
) -> models.User:
    """
    Expand a user from the provided JWT token.
    """

    try:
        user = models.User.objects.get(sub=token.sub, iss=token.iss)
        if user.changed_hash != token.changed_hash:
            # User has changed, update the user object
            user.first_name = token.preferred_username
            user.changed_hash = token.changed_hash
            set_user_groups(user, token.roles)

            if token.active_org:
                current_org, _ = models.Organization.objects.get_or_create(
                    slug=token.active_org
                )

                user.active_organization = current_org

            user.save()

        return user

    except models.User.DoesNotExist:

        user = models.User(
            sub=token.sub,
            username=(token_to_username(token)),
            iss=token.iss,
        )
        user.set_unusable_password()
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash

        if token.active_org:
            current_org, _ = models.Organization.objects.get_or_create(
                slug=token.active_org
            )

            user.active_organization = current_org

        user.save()
        set_user_groups(user, token.roles)
        return user


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
