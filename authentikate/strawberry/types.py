from authentikate import models
import kante


@kante.django_type(models.Device)
class Device:
    """This is the devicetype"""

    id: str
    device_id: str


@kante.django_type(models.App)
class App:
    """This is the apptype"""

    id: str
    identifier: str


@kante.django_type(models.Release)
class Release:
    """This is the release type"""

    app: App
    id: str
    version: str


@kante.django_type(models.Organization)
class Organization:
    """This is the organization type"""

    id: str
    slug: str


@kante.django_type(models.User)
class User:
    """This is the user type"""

    sub: str
    preferred_username: str
    active_organization: Organization | None = None


@kante.django_type(models.Client)
class Client:
    """This is the client type"""

    release: Release | None = None
    client_id: str
    name: str
