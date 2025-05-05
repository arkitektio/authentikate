import asyncio
from typing import AsyncGenerator
from kante.context import WsContext
from kante.types import Info
import strawberry
from strawberry import ID, scalars
from typing import cast
from kante.channel import build_channel
from pydantic import BaseModel
from strawberry.experimental import pydantic
import strawberry_django
from authentikate.strawberry import get_user, AuthentikateExtension
from authentikate import models



@strawberry_django.type(models.User)
class User:
    sub: str


@strawberry.type
class Query:
    
    
    @strawberry_django.field
    def me(self, info: Info) -> User | None:
        """Get the current user"""
        
        user = get_user()
        return cast(User, user) if user else None
        
        


@strawberry.type
class Mutation:
    
    @strawberry_django.mutation
    def create_user(self, info: Info, name: str) -> User:
        user = models.User.objects.create(username=name)
        return cast(User, user)
        
    
    
            
            


schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[
        AuthentikateExtension,   
    ]
)
