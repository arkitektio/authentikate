import contextvars
from authentikate.base_models import JWTToken
from authentikate.models import User, Client



token_var: contextvars.ContextVar[JWTToken | None] = contextvars.ContextVar("token_var", default=None)
user_var: contextvars.ContextVar[User | None] = contextvars.ContextVar("user_var", default=None)
client_var: contextvars.ContextVar[Client | None] = contextvars.ContextVar("client_var", default=None)


def get_token() -> JWTToken | None:
    """
    Get the current token from the context variable

    Returns
    -------
    JWTToken | None
        The current token
    """
    return token_var.get()

        
def get_user() -> User | None:
    """
    Get the current user from the context variable

    Returns
    -------
    User | None
        The current user
    """
    return user_var.get()

def get_client() -> Client | None:
    """
    Get the current client from the context variable

    Returns
    -------
    User | None
        The current user
    """
    return client_var.get()
    




