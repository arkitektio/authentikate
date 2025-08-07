
from authentikate import models
import kante


@kante.django_type(models.Organization)
class Organization:
    """ This is the organization type """
    id: str
    slug: str

@kante.django_type(models.User)
class User:
    """ This is the user type """
    sub: str
    preferred_username: str
    active_organization: Organization | None = None
    
    
    
@kante.django_type(models.Client)
class Client:
    """ This is the client type """
    client_id: str
    name: str