import contextvars
from authentikate.base_models import JWTToken
from authentikate.protocols import UserModel, ClientModel



token_var: contextvars.ContextVar[JWTToken | None] = contextvars.ContextVar("token_var", default=None)
user_var: contextvars.ContextVar[UserModel | None] = contextvars.ContextVar("user_var", default=None)
client_var: contextvars.ContextVar[ClientModel | None] = contextvars.ContextVar("client_var", default=None)
organization_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("organization_var", default=None)


def get_token() -> JWTToken | None:
    """
    Get the current token from the context variable

    Returns
    -------
    JWTToken | None
        The current token
    """
    return token_var.get()

        
def get_user() -> UserModel | None:
    """
    Get the current user from the context variable

    Returns
    -------
    User | None
        The current user
    """
    return user_var.get()

def get_client() -> ClientModel | None:
    """
    Get the current client from the context variable

    Returns
    -------
    User | None
        The current user
    """
    return client_var.get()


def get_organization() -> str | None:
    """
    Get the current organization from the context variable

    Returns
    -------
    str | None
        The current organization
    """
    return organization_var.get()
    




