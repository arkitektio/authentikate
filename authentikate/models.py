from django.db import models  # Create your models here.
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """A reflection on the real User"""

    sub = models.CharField(max_length=1000, null=True, blank=True)
    iss = models.CharField(max_length=1000, null=True, blank=True)
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


class App(models.Model):
    """ An Oauth2 App
    
    An Oauth2 App is a model to represent an Oauth2 app that is
    registered when a JWT token is authenticated. It retrieves
    the client_id from the token and uses it to create a new
    app or retrieve an existing app. This allows for the grouping
    of users by app.
    
    """
    iss = models.CharField(max_length=2000, null=True, blank=True)
    client_id = models.CharField(unique=True, max_length=2000)
    name = models.CharField(max_length=2000, null=True, blank=True)

    class Meta:
        """Meta class for App"""
        unique_together = ("iss", "client_id")

    def __str__(self) -> str:
        """String representation of App"""
        return f"{self.name}"
