"""This module contains the strawberry integration for authentikate

This module contains the strawberry integration for authentikate. It contains
the following submodules:

- :mod:`authentikate.strawberry.filters`: Contains the filters for the models
- :mod:`authentikate.strawberry.permission`: Contains permission classes to check for scopes
- :mod:`authentikate.strawberry.types`: Contains the types for the models
"""


from .permissions import NeedsScopes, IsAuthenticated


__all__ = ["NeedsScopes", "IsAuthenticated"]


