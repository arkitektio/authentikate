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
    preferred_username: str
    name: str | None = strawberry_django.field(description="The full name, if the issuer sends one.")
    given_name: str | None = strawberry_django.field(field_name="first_name", description="The given name, if the issuer sends one.")
    family_name: str | None = strawberry_django.field(field_name="last_name", description="The family name, if the issuer sends one.")
    nickname: str | None = strawberry_django.field(description="A casual name, if the issuer sends one.")
    picture: str | None = strawberry_django.field(description="URL of the profile picture, if the issuer sends one.")
    locale: str | None = strawberry_django.field(description="The user's locale (BCP47), if the issuer sends one.")
    zoneinfo: str | None = strawberry_django.field(description="The user's IANA time zone, if the issuer sends one.")
    active_organization: Organization | None = None


@kante.django_type(models.Client)
class Client:
    """An OAuth2 client (app instance) that requested a token."""

    id: strawberry.ID
    release: Release | None = None
    client_id: str
