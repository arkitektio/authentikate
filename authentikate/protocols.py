from typing import Protocol




class UserModel(Protocol):
    """A protocol for the user model"""
    id: int
    """The id of the user"""
    
    
    
    
class ClientModel(Protocol):
    """A protocol for the client model"""

    id: int
    """The id of the client"""

    client_id: str
    """The name of the client"""
    
    
    
    def has_scope(self, scope: str) -> bool:
        """Check if the user has the given scope"""
        ...
    


class OrganizationModel(Protocol):
    """A protocol for the organizaition model"""

    id: int
    """The id of the client"""

    slug: str
    """The name of orgnaization"""
    
    
class MembershipModel(Protocol):    
    """A protocol for the membership model"""
    
    id: int
    """The id of the membership"""
    