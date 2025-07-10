import logging
from typing import Literal, Optional, Type, Union, Annotated
from pydantic import BaseModel, Field, ConfigDict, field_validator, AliasChoices, Discriminator, FilePath
import datetime
from typing import Dict, Any
from joserfc.jwk import KeySet, RSAKey, OctKey, ECKey
from joserfc import jwt
from joserfc.jwk import GuestProtocol


logger = logging.getLogger(__name__)


class JWTToken(BaseModel):
    """A JWT token

    This is a pydantic model that represents a JWT token.
    It is used to validate the token and to extract information from it.
    The token is decoded using the `decode_token` function.

    """
    model_config = ConfigDict(extra="forbid")

    sub: str
    """A unique identifier for the user (is unique for the issuer)"""
    iss: str
    """The issuer of the token"""
    
    
    exp: datetime.datetime
    """The expiration time of the token"""
    
    
    active_org: str | None = None
    """The active organization of the user, if any"""
    
    client_id: str
    """The client_id of the app that requested the token"""
    preferred_username: str
    """The username of the user"""
    roles: list[str]
    """The roles of the user"""
    scope: str
    """The scope of the token"""
    
    iat: datetime.datetime
    """The issued at time of the token"""

    aud: list[str] | None = None
    """The audience of the token"""
    
    jti: str | None = None
    """The unique identifier for the token"""

    raw: str
    """ The raw original token string """
    
    
    @field_validator("aud", mode="before")
    def aud_to_list(cls: Type["JWTToken"], v: str | list[str] | None) -> list[str] | None:
        """Convert the aud to a list"""
        if not v:
            return None
        if isinstance(v, str):
            return [v]
        
        return v

    @field_validator("sub", mode="before")
    def sub_to_username(cls: Type["JWTToken"], v: str) -> str:
        """Convert the sub to a username compatible string"""
        if isinstance(v, int):
            return str(v)
        return v
    
    @field_validator("iat", mode="before")
    def iat_to_datetime(cls: Type["JWTToken"], v: int) -> datetime.datetime:
        """Convert the iat to a datetime object"""
        if v is None:
            return None
        if isinstance(v, int):
            return datetime.datetime.fromtimestamp(v)
        return v
    
    
    @field_validator("exp", mode="before")
    def exp_to_datetime(cls: Type["JWTToken"], v: int) -> datetime.datetime:
        """Convert the exp to a datetime object"""
        if isinstance(v, int):
            return datetime.datetime.fromtimestamp(v)
        return v

    @property
    def changed_hash(self) -> str:
        """A hash that changes when the user changes"""
        return str(hash(self.sub + self.preferred_username + " ".join(self.roles) + (self.active_org or "")))

    @property
    def scopes(self) -> list[str]:
        """The scopes of the token. Each scope is a string separated by a space"""
        return self.scope.split(" ")



class StaticToken(JWTToken):
    """A static JWT token"""

    sub: str
    iss: str
    iat: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now()
    )
    exp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now() + datetime.timedelta(days=1)
    )
    client_id: str = "static"
    preferred_username: str = "static_user"
    scope: str = "openid profile email"
    roles: list[str] = Field(default_factory=lambda: ["static"])
    raw: str = Field(default_factory=lambda: "static_token")
    
    

class ImitationRequest(BaseModel):
    """ An imitation request"""
    sub: str
    iss: str
    
   
   
class Issuer(BaseModel):
    """An issuer

    This is a pydantic model that represents an issuer.
    It is used to validate the issuer and to extract information from it.
    """
    model_config = ConfigDict(extra="forbid")
    kind: str 
    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    """The issuer of the token""" 
    
    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""
        raise NotImplementedError("get_jwks not implemented. Must be implemented in subclass")
    
class JWKIssuer(Issuer):
    """An issuer

    This is a pydantic model that represents an issuer.
    It is used to validate the issuer and to extract information from it.
    """
    kind: Literal["jwks_dict"] = Field(
        default="jwks_dict",
    )
    

    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    """The issuer of the token"""
    
    jwks: Dict[str, Any] = Field(
        validation_alias=AliasChoices("jwks", "JWKS", "JWKS_DICT")
    )
    """The jwks of the issuer"""
    
    
    @field_validator("jwks", mode="before")
    def validate_jwks_dict(cls: Type["JWKIssuer"], v: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the jwks dict"""
        if not isinstance(v, dict):
            raise ValueError("jwks_dict must be a dict")
        if "keys" not in v:
            raise ValueError("jwks_dict must contain a keys field")
        if not isinstance(v["keys"], list):
            raise ValueError("jwks_dict keys must be a list")
        return v
    
    
    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""
        return self.jwks["keys"]
    
    
    
class RSAKeyIssuer(Issuer):
    """An issuer

    This is a pydantic model that represents an issuer.
    It is used to validate the issuer and to extract information from it.
    """
    model_config = ConfigDict(extra="forbid")
    kind: Literal["rsa"] = Field(
        default="rsa",
    )

    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    key_id: str = Field(
        default="1",
        validation_alias=AliasChoices("key_id", "kid", "KID")
    )
    """The issuer of the token"""
    public_key: str = Field(
        validation_alias=AliasChoices("public_key", "PUBLIC_KEY")
    )
    
    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""
        t = RSAKey.import_key(self.public_key)
        return [t.as_dict(kid=self.key_id)]
    
    
    
class RSAKeyFileIssuer(Issuer):
    """An issuer

    This is a pydantic model that represents an issuer.
    It is used to validate the issuer and to extract information from it.
    """
    model_config = ConfigDict(extra="forbid")
    kind: Literal["rsa_file"] = Field(
        default="rsa_file",
    )

    iss: str = Field(
        validation_alias=AliasChoices("iss", "issuer", "issuer_url", "ISSUER")
    )
    key_id: str = Field(
        default="1",
        validation_alias=AliasChoices("key_id", "kid", "KID")
    )
    """The issuer of the token"""
    public_key_pem_file: FilePath = Field(
        validation_alias=AliasChoices("public_key_pem_file", "PUBLIC_KEY_PEM_FILE")
    )
    
    def get_as_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""
        
        with open(self.public_key_pem_file, "rb") as f:
            public_key = f.read()
        
        
        
        t = RSAKey.import_key(public_key)
        return [t.as_dict(kid=self.key_id)]
    
    
    
       
    
    
IssuerUnion = Annotated[Union[JWKIssuer, RSAKeyIssuer, RSAKeyFileIssuer], Discriminator("kind")]


class AuthentikateSettings(BaseModel):
    """The settings for authentikate

    This is a pydantic model that represents the settings for authentikate.
    It is used to configure the library.
    """
    model_config = ConfigDict(extra="forbid")
    
    issuers: list[IssuerUnion] = Field(validation_alias=AliasChoices(
        "issuers", "iss", "issuer", "issuer_url", "ISSUERS", 
    ))
    authorization_headers: list[str] = Field(
        default_factory=lambda: [
            "Authorization",
            "X-Authorization",
            "AUTHORIZATION",
            "authorization",
        ],
        validation_alias=AliasChoices(
            "authorization_headers", "AUTHORIZATION_HEADERS", "AUTHORIZATION_HEADERS"
        )
    )
    static_tokens: dict[str, StaticToken] = Field(default_factory=dict, validation_alias=AliasChoices(
        "static_tokens", "STATIC_TOKENS", "STATIC_TOKENS"
    ))
    """A map of static tokens to their decoded values. Should only be used in tests."""
    
    
    
    
    
    
    def get_jwks(self) -> list[Dict[str, Any]]:
        """Get the jwks of the issuer"""
            
        merged_jwks = {}
        
        for issuer in self.issuers:
            keys = issuer.get_as_jwks()
            
            
            if not isinstance(keys, list):
                raise ValueError("keys must be a list")
            
            for key in keys:
                if key.get("kid") is None:
                    raise ValueError("key must contain a kid field")
                
                if key["kid"] in merged_jwks:
                    raise ValueError(f"Duplicate kid found: {key['kid']}")
                
                merged_jwks[key["kid"]] = key
                
        if not merged_jwks:
            raise ValueError("No keys found in jwks")
        
        
        validated_keys = []
        
        for key in merged_jwks.values():
            validated_keys.append(key)
                
            
            
            
        return validated_keys
    
    
    
    def load_key(self, obj: GuestProtocol) -> KeySet:
        """Resolve the key from the header"""
        kid = obj.headers().get("kid")
        if not kid:
            raise ValueError("Missing kid in header")
        
        
        
        
        key_set = KeySet.import_key_set({"keys": self.get_jwks()})
        return key_set

