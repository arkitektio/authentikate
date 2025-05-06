from typing import AsyncIterator, Iterator, Union
from strawberry.extensions import SchemaExtension
from kante.context import WsContext, HttpContext
from authentikate.vars import token_var, user_var, client_var

from authentikate.utils import authenticate_token_or_none, authenticate_header_or_none
from authentikate.expand import aexpand_user_from_token, aexpand_client_from_token

class AuthentikateExtension(SchemaExtension):
    """ This is the extension class for the authentikate extension """
    
    
    async def on_operation(self) -> Union[AsyncIterator[None], Iterator[None]]:
        """ Set the token in the context variable """
        
        context = self.execution_context.context
        
        reset_user = None
        reset_client = None
        reset_token = None
        
        if isinstance(context, WsContext):
            # WebSocket context
            # Do something with the WebSocket context
            
            token = authenticate_token_or_none(
                context.connection_params.get("token", ""),
            )
            reset_token = token_var.set(token)
            if token:
                user = await aexpand_user_from_token(token)
                client = await aexpand_client_from_token(token)
                
                reset_client = client_var.set(client)
                reset_user = user_var.set(user)
                
                context.request.set_user(user)  
                context.request.set_client(client)
                
            
            
        
        elif isinstance(context, HttpContext):
            # HTTP context
            # Do something with the HTTP context
            token = authenticate_header_or_none(
                context.headers,
            )
            reset_token = token_var.set(token)
            if token:
                user = await aexpand_user_from_token(token)
                client = await aexpand_client_from_token(token)
                
                reset_client = client_var.set(client)
                reset_user = user_var.set(user)
                
                context.request.set_user(user)  
                context.request.set_client(client)
        else:
            raise ValueError("Unknown context type. Cannot determine if it's WebSocket or HTTP.")
           
        
        yield 
        
        
        # Cleanup
        if reset_user:
            user_var.reset(reset_user)
            
        if reset_client:
            client_var.reset(reset_client)
            
        if reset_token:
            token_var.reset(reset_token)
        
        return 
        
       
       

        