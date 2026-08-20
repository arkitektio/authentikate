import contextvars
from authentikate.base_models import JWTToken
from authentikate.models import Client
from authentikate.protocols import UserModel, OrganizationModel, MembershipModel


token_var: contextvars.ContextVar[JWTToken | None] = contextvars.ContextVar(
    "token_var", default=None
)
user_var: contextvars.ContextVar[UserModel | None] = contextvars.ContextVar(
    "user_var", default=None
)
client_var: contextvars.ContextVar[Client | None] = contextvars.ContextVar(
    "client_var", default=None
)
organization_var: contextvars.ContextVar[OrganizationModel | None] = (
    contextvars.ContextVar("organization_var", default=None)
)
membership_var: contextvars.ContextVar[MembershipModel | None] = contextvars.ContextVar(
    "membership_var", default=None
)


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


def get_client() -> Client | None:
    """
    Get the current client from the context variable

    Returns
    -------
    User | None
        The current user
    """
    return client_var.get()


def get_organization() -> OrganizationModel | None:
    """
    Get the current organization from the context variable

    Returns
    -------
    str | None
        The current organization
    """
    return organization_var.get()


def get_membership() -> MembershipModel | None:
    """
    Get the current membership from the context variable

    The membership carries the roles the user holds *within* the request's
    active organization, which is what org-scoped role checks read.

    Returns
    -------
    MembershipModel | None
        The current membership
    """
    return membership_var.get()
