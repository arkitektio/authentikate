from django.contrib.auth.models import Group
from authentikate import base_models, models
import logging
from authentikate.protocols import (
    UserModel,
    ClientModel,
    OrganizationModel,
    MembershipModel,
)
import asyncio

logger = logging.getLogger(__name__)


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
    """Add a list of roles to a user

    Roles are added as groups

    Parameters
    ----------
    user : models.User
        The user to add the roles to
    roles : list[str]
        The roles to add
    """
    for role in roles:
        g, _ = await Group.objects.aget_or_create(name=role)
        await user.groups.aadd(g)


def set_user_groups(user: models.User, roles: list[str]) -> None:
    """Add a list of roles to a user

    Roles are added as groups

    Parameters
    ----------
    user : models.User
        The user to add the roles to
    roles : list[str]
        The roles to add
    """
    for role in roles:
        g, _ = Group.objects.get_or_create(name=role)
        user.groups.add(g)


async def aexpand_organization_from_token(
    token: base_models.JWTToken,
) -> models.Organization:
    """
    Expand an organization from the provided JWT token.
    """
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
    assert membership.blocked is False, "Membership is blocked"
    return membership


async def aexpand_user_from_token(
    token: base_models.JWTToken,
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

            if token.active_org:
                current_org, _ = await models.Organization.objects.aget_or_create(
                    slug=token.active_org or "",
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

        if token.active_org:
            current_org, _ = await models.Organization.objects.aget_or_create(
                slug=token.active_org or "",
            )

            user.active_organization = current_org

        await user.asave()
        return user


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
                    identifier=token.active_org
                )

                user.active_organization = current_org

            user.save()

        return user

    except models.User.DoesNotExist:

        user = models.User(
            sub=token.sub,
            username=(token_to_username(token)),
            iss=token.iss,
            first_name=token.preferred_username,
        )
        user.set_unusable_password()
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash

        if token.active_org:
            current_org, _ = models.Organization.objects.get_or_create(
                identifier=token.active_org
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
    try:
        client = await models.Client.objects.prefetch_related("device", "release").aget(
            client_id=token.client_id, iss=token.iss
        )

        if not client.device and token.client_device:
            device, _ = await models.Device.objects.aget_or_create(
                device_id=token.client_device
            )
            client.device = device
            await client.asave()

        if not client.release and token.client_app and token.client_release:
            app, _ = await models.App.objects.aget_or_create(
                identifier=token.client_app
            )
            release, _ = await models.Release.objects.aget_or_create(
                app=app, version=token.client_release
            )

            client.release = release
            await client.asave()

        return client
    except models.Client.DoesNotExist:
        if token.client_app and token.client_release:
            app, _ = await models.App.objects.aget_or_create(
                identifier=token.client_app
            )
            release, _ = await models.Release.objects.aget_or_create(
                app=app, version=token.client_release
            )

        if token.client_device:
            device, _ = await models.Device.objects.aget_or_create(
                device_id=token.client_device
            )

        else:
            app = None
            release = None
            device = None

        return await models.Client.objects.acreate(
            client_id=token.client_id, iss=token.iss, release=release, device=device
        )


def expand_client_from_token(
    token: base_models.JWTToken,
) -> models.Client:
    """
    Expand a client from the provided JWT token.
    """
    try:
        client = models.Client.objects.prefetch_related("device", "release").get(
            client_id=token.client_id, iss=token.iss
        )

        if not client.device and token.client_device:
            device, _ = models.Device.objects.get_or_create(
                device_id=token.client_device
            )
            client.device = device
            client.save()

        if not client.release and token.client_app and token.client_release:
            app, _ = models.App.objects.get_or_create(identifier=token.client_app)
            release, _ = models.Release.objects.get_or_create(
                app=app, version=token.client_release
            )

            client.release = release
            client.save()

        return client
    except models.Client.DoesNotExist:
        if token.client_app and token.client_release:
            app, _ = models.App.objects.get_or_create(identifier=token.client_app)
            release, _ = models.Release.objects.get_or_create(
                app=app, version=token.client_release
            )

        if token.client_device:
            device, _ = models.Device.objects.get_or_create(
                device_id=token.client_device
            )

        else:
            app = None
            release = None
            device = None

        return models.Client.objects.create(
            client_id=token.client_id, iss=token.iss, release=release, device=device
        )
