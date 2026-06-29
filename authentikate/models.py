from django.db import models  # Create your models here.
from django.contrib.auth.models import AbstractUser


class Organization(models.Model):
    """An Organization model to represent an organization in the system"""

    slug = models.CharField(max_length=1000, unique=True)
    """The unique slug of the organization (mirrors the token's active_org claim)"""

    def __str__(self) -> str:
        """String representation of Organization"""
        return self.slug


class User(AbstractUser):
    """A reflection on the real User"""

    sub = models.CharField(max_length=1000, null=True, blank=True)
    """The sub claim of the token (unique per issuer)"""
    iss = models.CharField(max_length=1000, null=True, blank=True)
    """The issuer that authenticated this user"""
    active_organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="active_users",
    )
    """The organization the user is currently acting in"""
    changed_hash = models.CharField(max_length=1000, null=True, blank=True)
    """A stable hash of the token's user metadata, used to skip needless updates"""

    class Meta:
        """Meta class for User"""

        constraints = [
            models.UniqueConstraint(
                fields=["sub", "iss"],
                condition=models.Q(sub__isnull=False, iss__isnull=False),
                name="unique_sub_iss_if_both_not_null",
            )
        ]
        permissions = [("imitate", "Can imitate me")]


class Membership(models.Model):
    """A Membership model to represent a user's membership in an organization"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="memberships")
    """The user that is a member of the organization"""
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name="memberships"
    )
    """The organization the user belongs to"""
    blocked = models.BooleanField(default=False)
    """Whether the membership is blocked (blocked members cannot authenticate)"""
    roles = models.JSONField(default=list)
    """The roles the user holds within this organization (from the token)"""

    class Meta:
        """Meta class for Membership"""

        unique_together = ("user", "organization")

    def __str__(self) -> str:
        """String representation of Membership"""
        return f"{self.user} in {self.organization}"


class Device(models.Model):
    """A Device model to represent a user's device in the system"""

    device_id = models.CharField(max_length=2000, unique=True)
    """The unique device identifier (from the token's client_device claim)"""

    def __str__(self) -> str:
        """String representation of Device"""
        return f"{self.device_id}"


class App(models.Model):
    """An App model to represent an application in the system"""

    identifier = models.CharField(max_length=2000, unique=True)
    """The application identifier (from the token's client_app claim)"""

    def __str__(self) -> str:
        """String representation of App"""
        return f"{self.identifier}"


class Release(models.Model):
    """A Release model to represent a release of an application in the system"""

    app = models.ForeignKey(App, on_delete=models.CASCADE, related_name="releases")
    """The app this release belongs to"""
    version = models.CharField(max_length=2000)
    """The version of the release (from the token's client_release claim)"""

    class Meta:
        """Meta class for Release"""

        unique_together = ("app", "version")


class Client(models.Model):
    """An Oauth2 Client

    An Oauth2 Client is a model to represent an Oauth2 client that is
    registered when a JWT token is authenticated. It retrieves
    the client_id from the token and uses it to create a new
    app or retrieve an existing app. This allows for the grouping
    of users by app.

    """

    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    """The device the client was last seen on, if any"""
    release = models.ForeignKey(
        Release,
        on_delete=models.SET_NULL,
        related_name="clients",
        null=True,
        blank=True,
    )
    """The app release the client runs, if any"""
    iss = models.CharField(max_length=2000, null=True, blank=True)
    """The issuer that registered this client"""
    client_id = models.CharField(max_length=2000)
    """The OAuth2 client_id (unique together with iss)"""
    name = models.CharField(max_length=2000, null=True, blank=True)
    """A human readable name for the client, if any"""

    class Meta:
        """Meta class for Client"""

        unique_together = ("iss", "client_id")

    def __str__(self) -> str:
        """String representation of Client"""
        return f"{self.name}"
