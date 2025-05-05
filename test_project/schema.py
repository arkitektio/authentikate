from kante.types import Info
import strawberry
from typing import cast
import strawberry_django
from authentikate.vars import get_user, get_client
from authentikate import models
from authentikate.strawberry.extension import AuthentikateExtension



@strawberry_django.type(models.User)
class User:
    """ This is the user type """
    sub: str


@strawberry_django.type(models.Client)
class Client:
    """ This is the client type """
    client_id: str



@strawberry.type
class Query:
    """ This is the query class """
    
    
    @strawberry_django.field
    def me(self, info: Info) -> User | None:
        """Get the current user"""
        
        user = get_user()
        return cast(User, user) if user else None
    
    
    @strawberry_django.field
    def client(self, info: Info) -> Client | None:
        """Get the current client"""
        
        client = get_client()
        return cast(Client, client) if client else None
        
        


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
