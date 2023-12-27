import strawberry
from strawberry import auto
from strawberry_django.filters import FilterLookup
from authentikate import models


@strawberry.django.order(models.User)
class UserOrder:
    """Ordering options for users

    This class is used to order users in a query.
    """

    date_joined: auto
    """Order by date_joined"""



@strawberry.django.filter(models.User)
class UserFilter:
    """Filter options for users

    This class is used to filter users in a query.
    """
    username: FilterLookup[str]
