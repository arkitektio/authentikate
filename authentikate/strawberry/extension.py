from typing import Any, AsyncIterator, cast
from strawberry.extensions import SchemaExtension
from kante.context import WsContext, HttpContext
from authentikate.vars import (
    token_var,
    user_var,
    client_var,
    organization_var,
    membership_var,
)
from authentikate.base_models import AuthentikateSettings, JWTToken
from authentikate.models import Client, User
from authentikate.utils import (
    authenticate_header,
    authenticate_token,
)
from authentikate.provenance import (
    aauthenticate_provenance_header_or_raise,
    verify_actor,
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
            expanded.user,
            expanded.client,
            cast(OrganizationModel, expanded.organization),
            cast(MembershipModel, expanded.membership),
        )

    async def aexpand_user_from_token(self, token: JWTToken) -> User:
        """Expand a user from the provided JWT token.

        Goes through the full token context rather than the bare user lookup, so
        the membership and blocked checks are applied here too.
        """
        from authentikate.expand import aexpand_token_context

        expanded = await aexpand_token_context(token)
        return expanded.user

    async def aexpand_client_from_token(self, token: JWTToken) -> Client:
        """Expand a client from the provided JWT token"""
        from authentikate.expand import aexpand_client_from_token

        # Call the async function to expand the client
        return await aexpand_client_from_token(token)

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

    async def _aattach_provenance(
        self,
        context: "WsContext | HttpContext",
        carrier: dict[str, str],
        token: JWTToken,
        settings: AuthentikateSettings,
    ) -> None:
        """Verify a provenance token and attach it to the request.

        ``carrier`` holds the provenance token under one of the configured
        header names -- request headers over HTTP, connection params over
        WebSocket.

        Fails closed on both counts: a header that is present but
        malformed/unverifiable raises ProvenanceValidationError, and a token
        whose ``act`` does not match the auth token presenting it raises
        ProvenanceActorMismatchError. Without the second check any holder of a
        valid provenance token could replay it under their own auth token.
        """
        if settings.provenance is None:
            return

        provenance = await aauthenticate_provenance_header_or_raise(carrier, settings)
        if provenance is None:
            return

        verify_actor(provenance, token)

        context.request.set_provenance(provenance)
        context.request.set_extension("provenance", provenance)

    async def on_operation(self) -> AsyncIterator[None]:
        """Set the token in the context variable"""

        context = self.execution_context.context

        reset_user = None
        reset_client = None
        reset_token = None
        reset_organization = None
        reset_membership = None

        try:
            settings = self.get_settings()

            # The token and the provenance carrier are the only things that
            # differ between transports; everything after this point is shared,
            # so the two paths cannot drift apart.
            if isinstance(context, WsContext):
                carrier = {
                    str(k): v
                    for k, v in context.connection_params.items()
                    if isinstance(v, str)
                }
                token = await authenticate_token(
                    context.connection_params.get("token", ""),
                    settings,
                )
            elif isinstance(context, HttpContext):
                carrier = dict(context.headers)
                token = await authenticate_header(carrier, settings)
            else:
                raise ValueError(
                    "Unknown context type. Cannot determine if it's WebSocket or HTTP."
                )

            reset_token = token_var.set(token)
            if token:
                user, client, organization, membership = (
                    await self.aexpand_token_context(token)
                )

                reset_client = client_var.set(client)
                reset_user = user_var.set(cast(UserModel, user))
                reset_organization = organization_var.set(organization)
                reset_membership = membership_var.set(membership)

                # The concrete models do satisfy kante's User/Client protocols,
                # but basedpyright does not run mypy's django-stubs plugin, so it
                # sees the raw descriptors (``CharField[str]`` rather than ``str``)
                # and no declared ``id``. These casts are for the checker, not a
                # real mismatch -- the genuine one, kante's invariant
                # ``Provenance.act``, was fixed in kante 2.1.1, which is why
                # ``set_provenance`` needs no ignore any more.
                context.request.set_user(cast(Any, user))
                context.request.set_client(cast(Any, client))
                context.request.set_membership(membership)
                context.request.set_organization(organization)
                context.request.set_extension("token", token)

                await self._aattach_provenance(context, carrier, token, settings)

            yield
        finally:
            if reset_user:
                user_var.reset(reset_user)

            if reset_client:
                client_var.reset(reset_client)

            if reset_token:
                token_var.reset(reset_token)

            if reset_organization:
                organization_var.reset(reset_organization)

            if reset_membership:
                membership_var.reset(reset_membership)

        return
