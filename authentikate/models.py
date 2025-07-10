from django.db import models  # Create your models here.
from django.contrib.auth.models import AbstractUser



class Organization(models.Model):
    """An Organization model to represent an organization in the system"""
    identifier = models.CharField(max_length=1000, unique=True)

    def __str__(self) -> str:
        """String representation of Organization"""
        return self.identifier


class User(AbstractUser):
    """A reflection on the real User"""

    sub = models.CharField(max_length=1000, null=True, blank=True)
    iss = models.CharField(max_length=1000, null=True, blank=True)
    active_organization = models.ForeignKey(
        Organization,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="active_users",
    )
    changed_hash = models.CharField(max_length=1000, null=True, blank=True)

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


class Client(models.Model):
    """An Oauth2 Client

    An Oauth2 Client is a model to represent an Oauth2 client that is
    registered when a JWT token is authenticated. It retrieves
    the client_id from the token and uses it to create a new
    app or retrieve an existing app. This allows for the grouping
    of users by app.

    """
    iss = models.CharField(max_length=2000, null=True, blank=True)
    client_id = models.CharField(unique=True, max_length=2000)
    name = models.CharField(max_length=2000, null=True, blank=True)

    class Meta:
        """Meta class for Client"""

        unique_together = ("iss", "client_id")

    def __str__(self) -> str:
        """String representation of Client"""
        return f"{self.name}"
