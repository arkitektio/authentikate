import strawberry
from typing import Awaitable, Callable, Any, Optional, List, Sequence
from authentikate.strawberry.errors import (
    INSUFFICIENT_ORGANIZATION_ROLE,
    INSUFFICIENT_ROLE,
    INSUFFICIENT_SCOPE,
    NOT_AUTHENTICATED,
    denied,
    unauthenticated,
)
from strawberry.schema_directive import Location
from kante.types import Info
from strawberry.extensions import FieldExtension
from strawberry.types.field import StrawberryField
from authentikate.base_models import JWTToken


@strawberry.schema_directive(locations=[Location.FIELD_DEFINITION])
class Auth:
    """A directive to enforce authentication and authorization on fields."""

    required_scopes: Optional[List[str]] = strawberry.directive_field(
        name="required_scopes", default=None
    )
    required_roles: Optional[List[str]] = strawberry.directive_field(
        name="required_roles", default=None
    )
    required_org_roles: Optional[List[str]] = strawberry.directive_field(
        name="required_org_roles", default=None
    )


def _as_list(value: Optional[List[str]] | str) -> Optional[List[str]]:
    """Accept a bare string wherever a list of names is expected."""
    if isinstance(value, str):
        return [value]
    return value


def get_org_roles(info: Info) -> List[str]:
    """The roles the user holds *within the request's active organization*.

    Read from the request's Membership rather than the token, so roles are
    scoped to one organization instead of applying globally. Returns an empty
    list when there is no membership on the request, which makes every
    org-scoped check fail closed.
    """
    try:
        membership = info.context.request.membership
    except (KeyError, ValueError, AttributeError):
        return []

    return list(getattr(membership, "roles", None) or [])


def has_role(info: Info, role: str) -> bool:
    """Whether the request's token carries ``role``.

    For resolver-level checks that don't fit a field directive.
    """
    token: JWTToken = info.context.request.get_extension("token")
    return token.has_any_role([role])


def has_org_role(info: Info, role: str) -> bool:
    """Whether the user holds ``role`` in the request's active organization."""
    return role in get_org_roles(info)


class _AuthChecks:
    """The authorization checks shared by every auth field extension.

    Kept in one place so the sync, async, and subscription entrypoints cannot
    drift apart -- each of them previously carried its own copy.
    """

    def __init__(
        self,
        scopes: Optional[List[str]] | str = None,
        roles: Optional[List[str]] | str = None,
        any_role_of: Optional[List[str]] = None,
        any_scope_of: Optional[List[str]] = None,
        org_roles: Optional[List[str]] | str = None,
        any_org_role_of: Optional[List[str]] = None,
    ) -> None:
        """Record the requirements this field places on the caller."""
        self.scopes: Optional[List[str]] = _as_list(scopes)
        self.roles: Optional[List[str]] = _as_list(roles)
        self.any_role_of: Optional[List[str]] = any_role_of
        self.any_scope_of: Optional[List[str]] = any_scope_of
        self.org_roles: Optional[List[str]] = _as_list(org_roles)
        self.any_org_role_of: Optional[List[str]] = any_org_role_of

    def _directive(self) -> Auth:
        """The schema directive describing these requirements."""
        return Auth(
            required_scopes=self.scopes,
            required_roles=self.roles,
            required_org_roles=self.org_roles,
        )

    def check(self, info: Info) -> None:
        """Raise a coded error unless the request satisfies every requirement.

        The errors name the requirement and carry it in ``extensions``, which is
        safe: the ``Auth`` schema directive already publishes the required scopes
        and roles into the introspectable schema.

        Raises
        ------
        AuthentikateGraphQLError
            ``UNAUTHENTICATED`` when the request carried no credentials,
            ``PERMISSION_DENIED`` when it lacks a required scope or role.
        """
        try:
            # Accessing `user` raises when nothing has populated the request,
            # which is what makes an unauthenticated request fail here.
            _ = info.context.request.user
            token: JWTToken = info.context.request.get_extension("token")
        except (KeyError, ValueError):
            # kante raises ValueError when nothing has populated the request;
            # either way the request is not authenticated.
            raise unauthenticated("Authentication required", NOT_AUTHENTICATED)

        if self.scopes and not token.has_scopes(self.scopes):
            raise denied(
                f"User does not have the required scopes: {self.scopes}",
                INSUFFICIENT_SCOPE,
                requiredScopes=self.scopes,
            )

        if self.any_scope_of and not token.has_any_scope(self.any_scope_of):
            raise denied(
                f"User does not have any of the required scopes: {self.any_scope_of}",
                INSUFFICIENT_SCOPE,
                requiredAnyScopeOf=self.any_scope_of,
            )

        if self.roles and not token.has_roles(self.roles):
            raise denied(
                f"User does not have the required roles: {', '.join(self.roles)}",
                INSUFFICIENT_ROLE,
                requiredRoles=self.roles,
            )

        if self.any_role_of and not token.has_any_role(self.any_role_of):
            raise denied(
                "User does not have any of the required roles: "
                f"{', '.join(self.any_role_of)}",
                INSUFFICIENT_ROLE,
                requiredAnyRoleOf=self.any_role_of,
            )

        if self.org_roles or self.any_org_role_of:
            self._check_org_roles(info)

    def _check_org_roles(self, info: Info) -> None:
        """Enforce the org-scoped role requirements against the membership."""
        org_roles: Sequence[str] = get_org_roles(info)

        if self.org_roles and not all(r in org_roles for r in self.org_roles):
            raise denied(
                "User does not have the required organization roles: "
                f"{', '.join(self.org_roles)}",
                INSUFFICIENT_ORGANIZATION_ROLE,
                requiredOrganizationRoles=self.org_roles,
            )

        if self.any_org_role_of and not any(
            r in org_roles for r in self.any_org_role_of
        ):
            raise denied(
                "User does not have any of the required organization roles: "
                f"{', '.join(self.any_org_role_of)}",
                INSUFFICIENT_ORGANIZATION_ROLE,
                requiredAnyOrganizationRoleOf=self.any_org_role_of,
            )


class AuthExtension(_AuthChecks, FieldExtension):
    """Enforce authentication and authorization on a query or mutation field.

    ``roles``/``any_role_of`` check the token's global roles;
    ``org_roles``/``any_org_role_of`` check the roles the user holds within the
    request's active organization.
    """

    def apply(self, field: StrawberryField) -> None:
        """Apply the Auth directive to the field.

        Args:
            field (StrawberryField): The authentication field to which the directive will be applied.
        """
        assert (
            not field.is_subscription
        ), "Auth directive cannot be applied to subscriptions use AuthSubscribeExtension instead."
        field.directives.append(self._directive())

    def resolve(
        self, next_: Callable[..., Any], source: Any, info: Info, **kwargs: Any
    ) -> Any:
        """Resolve the field with authentication checks."""
        self.check(info)
        return next_(source, info, **kwargs)

    async def resolve_async(
        self,
        next_: Callable[..., Awaitable[Any]],
        source: Any,
        info: Info,
        **kwargs: Any,
    ) -> Any:
        """Resolve the field with authentication checks."""
        self.check(info)
        return await next_(source, info, **kwargs)


class AuthSubscribeExtension(_AuthChecks, FieldExtension):
    """Enforce authentication and authorization on a subscription field."""

    def apply(self, field: StrawberryField) -> None:
        """Apply the Auth directive to the field.

        Args:
            field (StrawberryField): The authentication field to which the directive will be applied.
        """
        assert (
            field.is_subscription
        ), "AuthSubscribeExtension can only be applied to subscription fields."
        field.directives.append(self._directive())

    def resolve(
        self, next_: Callable[..., Any], source: Any, info: Info, **kwargs: Any
    ) -> Any:
        """Resolve the field with authentication checks."""
        self.check(info)
        return next_(source, info, **kwargs)

    async def resolve_async(
        self,
        next_: Callable[..., Awaitable[Any]],
        source: Any,
        info: Info,
        **kwargs: Any,
    ) -> Any:
        """Resolve the field with authentication checks."""
        self.check(info)
        # this is a workaround for the fact that strawberry does not support async resolvers for subscriptions
        return next_(source, info, **kwargs)


all_directives = [Auth]
