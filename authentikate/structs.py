import logging
import dataclasses
from typing import Type
from .models import User, App
from pydantic import BaseModel, validator, Field

logger = logging.getLogger(__name__)


class JWTToken(BaseModel):
    """A JWT token
    
    This is a pydantic model that represents a JWT token.
    It is used to validate the token and to extract information from it.
    The token is decoded using the `decode_token` function.

    """


    sub: str
    """A unique identifier for the user (is unique for the issuer)"""
    iss: str
    """The issuer of the token"""
    exp: int
    """The expiration time of the token"""
    client_id: str
    """The client_id of the app that requested the token"""
    preferred_username: str
    """The username of the user"""
    roles: list[str]
    """The roles of the user"""
    scope: str
    """The scopes of the token"""

    aud: str | None = None
    """The audience of the token"""

    @validator("sub", pre=True)
    def sub_to_username(cls: Type["JWTToken"], v: str) -> str:
        """Convert the sub to a username compatible string"""
        if isinstance(v, int):
            return str(v)
        return v

    @property
    def changed_hash(self) -> str:
        """A hash that changes when the user changes"""
        return str(hash(self.sub + self.preferred_username + " ".join(self.roles)))

    @property
    def scopes(self) -> list[str]:
        """The scopes of the token. Each scope is a string separated by a space"""
        return self.scope.split(" ")

    class Config:
        """Pydantic config"""
        extra = "ignore"


class AuthentikateSettings(BaseModel):
    """The settings for authentikate

    This is a pydantic model that represents the settings for authentikate.
    It is used to configure the library.
    """
    algorithms: list[str]
    public_key: str
    force_client: bool
    allow_imitate: bool
    imitate_headers: list[str] = Field(default_factory=lambda: ["X-Imitate-User"])
    authorization_headers: list[str] = Field(
        default_factory=lambda: ["Authorization", "X-Authorization", "AUTHORIZATION"]
    )
    imitate_permission: str = "authentikate.imitate"


@dataclasses.dataclass
class Auth:
    """
    Mimics the structure of `AbstractAccessToken` so you can use standard
    Django Oauth Toolkit permissions like `TokenHasScope`.
    """

    token: JWTToken
    user: User
    app: App

    def is_valid(self, scopes: list[str] | None =None) -> bool:
        """
        Check if the token is valid


        Parameters
        ----------
        scopes : list[str], optional
            The scopes to check, by default None

        Returns
        -------
        bool
            Whether the token is valid

        """
        return not self.is_expired() and self.has_scopes(scopes or [])

    def is_expired(self)-> bool:
        """
        Check if the token is expired

        As we are using JWT tokens, we do not need to check the expiration time
        as the token is already checked for expiration when it is decoded.

        Returns
        -------
        bool
            Whether the token is expired or not (will always return False)
        """
        # Token expiration is already checked
        return False

    def has_scopes(self, scopes: list[str])-> bool:
        """Does the token have the required scopes?

        Check if the token has the required scopes, if no scopes are provided
        it will return True.

        Parameters
        ----------
        scopes : list[str]
            The scopes to check

        Returns
        -------
        bool
            Does the token have the required scopes?
        """

        provided_scopes = set(self.token.scopes)
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)
