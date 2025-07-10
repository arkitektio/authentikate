from typing import Protocol




class UserModel(Protocol):
    """A protocol for the user model"""
    sub: str
    """A unique identifier for the user (is unique for the issuer)"""

    iss: str
    """The issuer of the token"""

    exp: str
    """The expiration time of the token"""

    client_id: str
    """The client_id of the app that requested the token"""

    preferred_username: str
    """The username of the user"""

    roles: list[str]
    """The roles of the user"""

    scope: str
    """The scope of the token"""

    iat: str
    """The issued at time of the token"""
    
    
    
class ClientModel(Protocol):
    """A protocol for the client model"""

    id: str
    """The id of the client"""

    name: str
    """The name of the client"""


class OrganizationModel(Protocol):
    """A protocol for the organizaition model"""

    id: str
    """The id of the client"""

    identifier: str
    """The name of orgnaization"""