from authentikate import models
import kante
import strawberry
import strawberry_django


@kante.django_type(models.Device)
class Device:
    """A device a client was registered on, identified by its device id."""

    id: strawberry.ID
    device_id: str


@kante.django_type(models.App)
class App:
    """An application known to the system, identified by its identifier."""

    id: strawberry.ID
    identifier: str


@kante.django_type(models.Release)
class Release:
    """A specific version (release) of an application."""

    id: strawberry.ID
    app: App
    version: str


@kante.django_type(models.Organization)
class Organization:
    """An organization that users can be members of, identified by its slug."""

    id: strawberry.ID
    slug: str


@kante.django_type(models.User)
class User:
    """An authenticated user, mirrored from the token's sub and iss claims."""

    id: strawberry.ID
    sub: str
    # The token's preferred_username is persisted on first_name (see expand.py)
    preferred_username: str = strawberry_django.field(field_name="first_name")
    active_organization: Organization | None = None


@kante.django_type(models.Client)
class Client:
    """An OAuth2 client (app instance) that requested a token."""

    id: strawberry.ID
    release: Release | None = None
    client_id: str
    name: str
