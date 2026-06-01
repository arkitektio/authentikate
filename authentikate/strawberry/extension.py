from typing import Any, AsyncIterator, cast
from strawberry.extensions import SchemaExtension
from kante.context import WsContext, HttpContext
from authentikate.vars import token_var, user_var, client_var, organization_var
from authentikate.base_models import AuthentikateSettings, JWTToken
from authentikate.models import Client, User
from authentikate.utils import (
    authenticate_header,
    authenticate_token,
    extract_task_from_rekuest_header,
)
from authentikate.protocols import UserModel, OrganizationModel, MembershipModel


class AuthentikateExtension(SchemaExtension):
    """This is the extension class for the authentikate extension"""

    def get_settings(self) -> "AuthentikateSettings":
        """Get the settings for the extension"""
        from authentikate.settings import get_settings

        # Call the function to get the settings
        settings = get_settings()
        return settings

    async def aexpand_token_context(
        self, token: JWTToken
    ) -> tuple[User, Client, OrganizationModel, MembershipModel]:
        """Expand the full auth context for a token through one helper."""
        from authentikate.expand import aexpand_token_context

        expanded = await aexpand_token_context(token)
        return (
            cast(User, expanded.user),
            cast(Client, expanded.client),
            cast(OrganizationModel, expanded.organization),
            cast(MembershipModel, expanded.membership),
        )

    async def aexpand_user_from_token(self, token: JWTToken) -> User:
        """Expand a user from the provided JWT token"""
        from authentikate.expand import aexpand_user_from_token

        # Call the async function to expand the user
        user = await aexpand_user_from_token(token)
        return cast(User, user)

    async def aexpand_client_from_token(self, token: JWTToken) -> Client:
        """Expand a client from the provided JWT token"""
        from authentikate.expand import aexpand_client_from_token

        # Call the async function to expand the client
        client = await aexpand_client_from_token(token)
        return cast(Client, client)

    async def aexpand_organization_from_token(
        self, token: JWTToken
    ) -> "OrganizationModel":
        """Expand an organization from the provided JWT token"""
        from authentikate.expand import aexpand_organization_from_token

        # Call the async function to expand the organization
        organization = await aexpand_organization_from_token(token)
        return cast(OrganizationModel, organization)

    async def aexpand_membership_from_user_and_organization(
        self, user: UserModel, organization: OrganizationModel, token: JWTToken
    ) -> "MembershipModel":
        """Expand a membership from the provided JWT token"""
        from authentikate.expand import aexpand_membership

        # Call the async function to expand the membership
        membership = await aexpand_membership(user, organization, token)
        return cast(MembershipModel, membership)

    async def on_operation(self) -> AsyncIterator[None]:
        """Set the token in the context variable"""

        context = self.execution_context.context

        reset_user = None
        reset_client = None
        reset_token = None
        reset_organization = None

        if isinstance(context, WsContext):
            # WebSocket context
            # Do something with the WebSocket context

            token = await authenticate_token(
                context.connection_params.get("token", ""),
                self.get_settings(),
            )
            reset_token = token_var.set(token)
            if token:
                user, client, organization, membership = (
                    await self.aexpand_token_context(token)
                )

                reset_client = client_var.set(client)
                reset_user = user_var.set(cast(UserModel, user))
                reset_organization = organization_var.set(organization)

                context.request.set_user(cast(Any, user))
                context.request.set_client(cast(Any, client))
                context.request.set_membership(membership)
                context.request.set_organization(organization)
                context.request.set_extension("token", token)

        elif isinstance(context, HttpContext):
            # HTTP context
            # Do something with the HTTP context
            task = extract_task_from_rekuest_header(
                dict(context.headers),
                self.get_settings(),
            )
            token = await authenticate_header(
                dict(context.headers),
                self.get_settings(),
                task=task,
            )
            reset_token = token_var.set(token)
            if token:
                user, client, organization, membership = (
                    await self.aexpand_token_context(token)
                )

                reset_client = client_var.set(client)
                reset_user = user_var.set(cast(UserModel, user))
                reset_organization = organization_var.set(organization)

                context.request.set_user(cast(Any, user))
                context.request.set_client(cast(Any, client))
                context.request.set_membership(membership)
                context.request.set_organization(organization)
                context.request.set_extension("token", token)
                if task is not None:
                    context.request.set_task(task)
                    context.request.set_extension("task", task)
        else:
            raise ValueError(
                "Unknown context type. Cannot determine if it's WebSocket or HTTP."
            )

        yield

        # Cleanup
        if reset_user:
            user_var.reset(reset_user)

        if reset_client:
            client_var.reset(reset_client)

        if reset_token:
            token_var.reset(reset_token)

        if reset_organization:
            organization_var.reset(reset_organization)

        return
