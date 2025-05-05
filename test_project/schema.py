from kante.types import Info
import strawberry
from typing import cast
import strawberry_django
from authentikate.strawberry import get_user, AuthentikateExtension
from authentikate import models



@strawberry_django.type(models.User)
class User:
    """ This is the user type """
    sub: str


@strawberry.type
class Query:
    """ This is the query class """
    
    
    @strawberry_django.field
    def me(self, info: Info) -> User | None:
        """Get the current user"""
        
        user = get_user()
        return cast(User, user) if user else None
        
        


@strawberry.type
class Mutation:
    """ This is the mutation class """
    
    @strawberry_django.mutation
    def create_user(self, info: Info, name: str) -> User:
        """Create a new user"""
        user = models.User.objects.create(username=name)
        return cast(User, user)
        
    
    
            
            


schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[
        AuthentikateExtension,   
    ]
)
