from contextvars import ContextVar, Token
from typing import Any, AsyncIterator, cast
from graphql import (
    DocumentNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLSchema,
    InlineFragmentNode,
    OperationDefinitionNode,
    SelectionSetNode,
)
from strawberry.extensions import SchemaExtension
from strawberry.schema.schema_converter import GraphQLCoreConverter
from strawberry.types import ExecutionContext
from strawberry.types.graphql import OperationType
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
from authentikate.errors import (
    AuthentikateError,
    AuthentikatePermissionDenied,
    ScopedReadOnly,
)
from authentikate.scoped import scoped_mode
from authentikate.strawberry.errors import to_graphql_error


def _reset(var: ContextVar[Any], token: Token[Any] | None) -> None:
    """Undo ``var.set`` for this operation, where that is still possible.

    A WebSocket operation's stream can be closed from another task -- the
    client disconnected mid-subscription, or after an error -- and then this
    runs in a context that never set ``var``. The context that did ends with the
    operation, so there is nothing left to undo; resetting the variable here
    would clobber the other context's value instead.
    """
    if token is None:
        return
    try:
        var.reset(token)
    except ValueError:
        pass


def _operation(document: DocumentNode, name: str | None) -> OperationDefinitionNode | None:
    """The operation of ``document`` that runs: the one called ``name``, else the only one."""
    for definition in document.definitions:
        if isinstance(definition, OperationDefinitionNode) and (
            name is None or (definition.name is not None and definition.name.value == name)
        ):
            return definition
    return None


def _root_field_names(
    selection_set: SelectionSetNode,
    fragments: dict[str, FragmentDefinitionNode],
    seen: frozenset[str] = frozenset(),
) -> list[str]:
    """The root fields an operation selects, through its fragments."""
    names: list[str] = []
    for selection in selection_set.selections:
        if isinstance(selection, FieldNode):
            names.append(selection.name.value)
        elif isinstance(selection, InlineFragmentNode):
            names.extend(_root_field_names(selection.selection_set, fragments, seen))
        elif isinstance(selection, FragmentSpreadNode):
            name = selection.name.value
            fragment = fragments.get(name)
            if fragment is not None and name not in seen:
                names.extend(_root_field_names(fragment.selection_set, fragments, seen | {name}))
    return names


def allows_scoped(execution_context: ExecutionContext) -> bool:
    """Whether every root field of the operation opted in to scoped members.

    A field opts in with ``AuthExtension(allow_scoped=True)``. One that did not,
    one that cannot be found, or an operation that cannot be read, does not.
    """
    document = execution_context.graphql_document
    if document is None:
        return False
    operation = _operation(document, execution_context.operation_name)
    if operation is None:
        return False
    core: GraphQLSchema = execution_context.schema._schema
    root = core.get_root_type(operation.operation)
    if root is None:
        return False
    fragments = {
        d.name.value: d for d in document.definitions if isinstance(d, FragmentDefinitionNode)
    }
    for name in _root_field_names(operation.selection_set, fragments):
        if name == "__typename":
            continue
        field = root.fields.get(name)
        definition = (field.extensions or {}).get(GraphQLCoreConverter.DEFINITION_BACKREF) if field else None
        if not any(getattr(e, "allow_scoped", False) for e in getattr(definition, "extensions", None) or ()):
            return False
    return True


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

    async def anarrow_scoped_token(
        self, token: JWTToken, organization: OrganizationModel
    ) -> JWTToken:
        """Drop a scoped token's grants whose sharer is blocked here (see :mod:`authentikate.expand`)."""
        from authentikate.expand import anarrow_scoped_token

        return await anarrow_scoped_token(token, cast(Any, organization))

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
            # Only the authentication/expansion step is translated. A failure
            # inside a resolver (after the yield) is the resolver's own error
            # and must not be relabelled as an auth failure.
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
                    narrowed = await self.anarrow_scoped_token(token, organization)
                    if narrowed is not token:
                        token_var.reset(reset_token)
                        token = narrowed
                        reset_token = token_var.set(token)

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

            except (AuthentikateError, AuthentikatePermissionDenied) as exc:
                raise to_graphql_error(exc) from exc

            yield
        finally:
            _reset(user_var, reset_user)
            _reset(client_var, reset_client)
            _reset(token_var, reset_token)
            _reset(organization_var, reset_organization)
            _reset(membership_var, reset_membership)

        return

    async def on_validate(self) -> AsyncIterator[None]:
        """Keep a scoped member's operation read-only.

        Here rather than in ``on_operation``: the operation's type is known only
        once the document is parsed. The refusal is recorded as the operation's
        validation errors, which strawberry answers with -- over HTTP and
        WebSocket alike -- instead of running it. (Raising here would bring a
        WebSocket down; raising in ``on_execute`` leaves the hooks entered before
        it, the optimizer's among them, unwound.)

        Subscriptions are refused with mutations, whatever their fields say --
        they stream the organization's events, which no queryset narrows. A
        mutation passes only when every root field opted in (``allow_scoped``). Under
        ``SCOPED_TOKENS: self`` the service applies its own rules instead.
        """
        token = token_var.get()
        operation_type = self.execution_context.operation_type
        if (
            token is not None
            and token.is_scoped
            and operation_type != OperationType.QUERY
            and scoped_mode(self.get_settings()) == "enforce"
            and (operation_type == OperationType.SUBSCRIPTION or not allows_scoped(self.execution_context))
        ):
            operation = self.execution_context.operation_type.value
            self.execution_context.pre_execution_errors = [
                to_graphql_error(ScopedReadOnly(f"{token.sub} sent a {operation} as a scoped member"))
            ]

        yield
