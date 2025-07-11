from kante.types import Info
import strawberry
from typing import AsyncGenerator, cast
import strawberry_django
from authentikate.vars import get_user, get_client
from authentikate import models
from authentikate.strawberry.extension import AuthentikateExtension
from authentikate.strawberry.types import User, Client
from authentikate.strawberry.directives import Auth, AuthExtension, all_directives



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
    
    
    @strawberry_django.mutation(extensions=[AuthExtension(scopes="write")])
    def require_write(self, info: Info) -> str:
        return "User"
    
    @strawberry_django.mutation(extensions=[AuthExtension(scopes="read")])
    def require_read(self, info: Info) -> str:
        return "User"
        
    
@strawberry.type
class Subscription:
    """ This is the subscription class """
    
    @strawberry.subscription
    async def yield_user(self, info: Info) -> AsyncGenerator[User,  None]:
        """Subscribe to user creation events"""
        # This is just a placeholder. In a real application, you would use channels or another method to send updates.
        yield cast(User, info.context.request.user)
    
            
            


schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
    extensions=[
        AuthentikateExtension,   
    ],
    schema_directives=all_directives,
)
