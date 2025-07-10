
from authentikate import models
import strawberry_django


@strawberry_django.type(models.Organization)
class Organization:
    """ This is the organization type """
    id: str
    identifier: str

@strawberry_django.type(models.User)
class User:
    """ This is the user type """
    sub: str
    preferred_username: str
    roles: list[str]
    active_organization: Organization | None = None
    
    
    
@strawberry_django.type(models.Client)
class Client:
    """ This is the client type """
    client_id: str
    name: str