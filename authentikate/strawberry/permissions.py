from strawberry.permission import BasePermission
from strawberry.types import Info
from typing import Any, Type


class IsAuthenticated(BasePermission):
    """Check if a user is authenticated

    Note:
       This permission is only available if you are setting
       the info.context.request.user to the user object

    TODO: Change this to use the auth object instead of the user object


    """


    message = "User is not authenticated"

    # This method can also be async!
    def has_permission(self, source: Any, info: Info, **kwargs) -> bool:
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
    message = "User is not authenticated"
    checked_scopes = []

    # This method can also be async!
    def has_permission(self, source: Any, info: Info, **kwargs) -> bool:
        print(info.context.request.scopes)
        return info.context.request.has_scopes(self.checked_scopes)


def NeedsScopes(scopes: str | list[str]) -> Type[HasScopes]:
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
