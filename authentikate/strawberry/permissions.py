"""Permissions for strawberry

This module contains permissions for strawberry
powered graphql endpoints.

"""

from strawberry.permission import BasePermission
from strawberry.types import Info
from typing import Any, Type, Protocol
from django.contrib.auth.models import User


class ContextRequest(Protocol):
    """A protocol for the request object"""

    user: User
    """The user object"""
    scopes: list[str]
    """The scopes of the request"""

    def has_scopes(self, scopes: list[str]) -> bool:
        """Check if the request has the required scopes"""
        ...

    def is_authenticated(self) -> bool:
        """Check if the request is authenticated"""
        ...


class ContextClass(Protocol):
    """A protocol for the context class"""

    request: ContextRequest
    """The request object"""


class IsAuthenticated(BasePermission):
    """Check if a user is authenticated

    Note:
       This permission is only available if you are setting
       the info.context.request.user to the user object

    TODO: Change this to use the auth object instead of the user object


    """

    message = "User is not authenticated"

    # This method can also be async!
    def has_permission(
        self, source: Any, info: Info[ContextClass, Any], **kwargs: Any
    ) -> bool:
        """Has permission

        Check if the user is authenticated

        Parameters
        ----------
        source : Any
            The source of the request
        info : Info
            The info object

        Returns
        -------
        bool
            Whether the user is authenticated or not

        """
        if info.context.request.user is not None:
            return info.context.request.user.is_authenticated
        return False


class HasScopes(BasePermission):
    """Check if a user has the required scopes

    Note:
        This permission is only available if you are setting
        the info.context.request.user to the user object

    """

    message = "User is not authenticated"
    checked_scopes: list[str] = []

    # This method can also be async!
    def has_permission(
        self, source: Any, info: Info[ContextClass, Any], **kwargs: Any
    ) -> bool:
        """Has permission

        Check if the user has the required scopes

        Parameters
        ----------
        source : Any
            The source of the request
        info : Info

        Returns
        -------
        bool
            Whether the user has the required scopes or not

        """

        print(info.context.request.scopes)
        return info.context.request.has_scopes(self.checked_scopes)


def NeedsScopes(scopes: str | list[str]) -> Type[HasScopes]:
    """Create a permission that requires scopes

    Please note that this permission is only available if you are setting
    the info.context.request.user to the user object


    Parameters
    ----------
    scopes : str | list[str]
        The scopes to check

    Returns
    -------
    Type[HasScopes]
        The permission

    """
    if isinstance(scopes, str):
        scopes = [scopes]
    return type(
        f"NeedsScopes{'_'.join(scopes)}",
        (HasScopes,),
        dict(
            message=f"App does not have the required scopes: {','.join(scopes)}",
            checked_scopes=scopes,
        ),
    )
