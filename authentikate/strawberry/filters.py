"""Filters

This module contains filters for the GraphQL API.

"""

from strawberry import auto
import strawberry_django
from strawberry_django.filters import FilterLookup
from authentikate import models


@strawberry_django.order(models.User)
class UserOrder:
    """Ordering options for users

    This class is used to order users in a query.
    """

    date_joined: auto
    """Order by date_joined"""


@strawberry_django.filter(models.User)
class UserFilter:
    """Filter options for users

    This class is used to filter users in a query.
    """

    username: FilterLookup[str]
