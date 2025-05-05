import contextvars
from authentikate.base_models import JWTToken
from authentikate.models import User
from authentikate.expand import aexpand_user_from_token, expand_user_from_token



token_var: contextvars.ContextVar[JWTToken | None] = contextvars.ContextVar("token_var", default=None)


def get_token() -> JWTToken | None:
    """
    Get the current token from the context variable

    Returns
    -------
    JWTToken | None
        The current token
    """
    return token_var.get()

    

def set_token(token: JWTToken | None) -> None:
    """
    Set the current token in the context variable
    Parameters
    ----------
    new_token : JWTToken
        The token to set
    """
    token_var.set(token)




async def aget_user() -> User | None:
    """
    Get the current user from the context variable

    Returns
    -------
    User | None
        The current user
    """
    token = get_token()
    return await aexpand_user_from_token(token) if token else None
    
    
def get_user() -> User | None:
    """
    Get the current user from the context variable

    Returns
    -------
    User | None
        The current user
    """
    token = get_token()
    return expand_user_from_token(token) if token else None


async def aget_imitate_user() -> User | None:
    """
    Get the current user from the context variable

    Returns
    -------
    User | None
        The current user
    """
    token = get_token()
    return await aexpand_user_from_token(token) if token else None


def get_imitate_user() -> User | None:
    """
    Get the current user from the context variable

    Returns
    -------
    User | None
        The current user
    """
    token = get_token()
    return expand_user_from_token(token) if token else None

