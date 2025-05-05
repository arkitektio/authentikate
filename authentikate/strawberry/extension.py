from typing import AsyncIterator, Iterator, Union
from strawberry.extensions import SchemaExtension
from kante.context import WsContext, HttpContext
from .vars import set_token

from authentikate.utils import authenticate_token_or_none, authenticate_header_or_none

class AuthentikateExtension(SchemaExtension):
    
    
    async def on_operation(self) -> Union[AsyncIterator[None], Iterator[None]]:
        
        context = self.execution_context.context
        
        
        
        if isinstance(context, WsContext):
            # WebSocket context
            # Do something with the WebSocket context
            
            token = authenticate_token_or_none(
                context.connection_params.get("token", ""),
            )
            set_token(token)
            
        
        elif isinstance(context, HttpContext):
            # HTTP context
            # Do something with the HTTP context
            token = authenticate_header_or_none(
                context.headers,
            )
            
            
            set_token(token)
            
        else:
            raise ValueError("Unknown context type. Cannot determine if it's WebSocket or HTTP.")
           
        
        yield 
        
        
        set_token(None)
        
        return 
        
       
       

        