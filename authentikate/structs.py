import logging
import dataclasses
from .models import User, App
from pydantic import BaseModel, validator, Field
from django.contrib.auth import get_user_model
from django.utils.functional import cached_property
from importlib import import_module

logger = logging.getLogger(__name__)


def import_model(model_str: str):
    module_str, model_str = model_str.rsplit(".", 1)
    module = import_module(module_str)
    return getattr(module, model_str)


def import_function(function_str: str):
    module_str, function_str = function_str.rsplit(".", 1)
    module = import_module(module_str)
    return getattr(module, function_str)


class JWTToken(BaseModel):
    sub: str
    iss: str
    exp: int
    client_id: str
    preferred_username: str
    roles: list[str]
    scope: str
    aud: str | None = None

    @validator("sub", pre=True)
    def sub_to_username(cls, v):
        if isinstance(v, int):
            return str(v)
        return v

    @property
    def changed_hash(self) -> str:
        return str(hash(self.sub + self.preferred_username + " ".join(self.roles)))

    @property
    def scopes(self) -> list[str]:
        return self.scope.split(" ")

    class Config:
        extra = "ignore"


class AuthentikateSettings(BaseModel):
    algorithms: list[str]
    public_key: str
    force_client: bool
    allow_imitate: bool
    imitate_headers: list[str] = Field(default_factory=lambda: ["X-Imitate-User"])
    authorization_headers: list[str] = Field(
        default_factory=lambda: [
            "Authorization",
            "X-Authorization",
            "AUTHORIZATION",
            "authorization",
        ]
    )
    imitate_permission: str = "authentikate.imitate"
    sub_field: str = "sub"
    iss_field: str = "iss"
    user_model_str: str | None = None
    jwt_base_model_str: str = "authentikate.structs.JWTToken"
    app_model_str: str = "authentikate.App"
    client_id_field: str = "client_id"
    app_iss_field: str = "iss"
    force_client: bool = False

    @cached_property
    def user_model(self):
        return get_user_model() or import_model(self.user_model_str)

    @cached_property
    def app_model(self):
        return import_model(self.app_model)

    @cached_property
    def jwt_base_model(self):
        return import_model(self.jwt_base_model_str)

    class Config:
        arbitrary_types_allowed = True
        keep_untouched = (cached_property,)


@dataclasses.dataclass
class Auth:
    """
    Mimics the structure of `AbstractAccessToken` so you can use standard
    Django Oauth Toolkit permissions like `TokenHasScope`.
    """

    token: JWTToken
    user: User
    app: App

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.
        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        # Token expiration is already checked
        return False

    def has_scopes(self, scopes):
        """
        Check if the token allows the provided scopes
        :param scopes: An iterable containing the scopes to check
        """

        provided_scopes = set(self.token.scopes)
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)
