from strawberry.permission import BasePermission
from strawberry.types import Info
from typing import Any, Type


class IsAuthenticated(BasePermission):
    message = "User is not authenticated"

    # This method can also be async!
    def has_permission(self, source: Any, info: Info, **kwargs) -> bool:
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
