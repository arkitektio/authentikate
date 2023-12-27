"""Types for strawberry-graphql

This module contains types for strawberry-graphql
that can be used and extended by other modules.

"""


from strawberry import auto
import strawberry_django
from authentikate.models import App as AppModel, User as UserModel


@strawberry_django.type(UserModel, pagination=True)
class User:
    """User type for strawberry"""

    id: auto


@strawberry_django.type(AppModel, pagination=True)
class App:
    """App type for strawberry"""

    id: auto
