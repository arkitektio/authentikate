from authentikate import models
import kante
import strawberry


@kante.django_type(models.Device)
class Device:
    """This is the devicetype"""

    id: strawberry.ID
    device_id: str


@kante.django_type(models.App)
class App:
    """This is the apptype"""

    id: strawberry.ID
    identifier: str


@kante.django_type(models.Release)
class Release:
    """This is the release type"""

    id: strawberry.ID
    app: App
    version: str


@kante.django_type(models.Organization)
class Organization:
    """This is the organization type"""

    id: strawberry.ID
    slug: str


@kante.django_type(models.User)
class User:
    """This is the user type"""

    id: strawberry.ID
    sub: str
    preferred_username: str
    active_organization: Organization | None = None


@kante.django_type(models.Client)
class Client:
    """This is the client type"""

    id: strawberry.ID
    release: Release | None = None
    client_id: str
    name: str
