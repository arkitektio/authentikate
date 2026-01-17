from typing import AsyncIterator, Iterator, Union
from strawberry.extensions import SchemaExtension
from kante.context import WsContext, HttpContext
from authentikate.vars import token_var, user_var, client_var, organization_var
from authentikate.base_models import JWTToken
from authentikate.utils import authenticate_header, authenticate_token, authenticate_token_or_none, authenticate_header_or_none
from authentikate.protocols import UserModel, ClientModel, OrganizationModel, MembershipModel
from typing import cast
from authentikate.base_models import AuthentikateSettings

class AuthentikateExtension(SchemaExtension):
    """ This is the extension class for the authentikate extension """
    
    
    def get_settings(self) -> "AuthentikateSettings":
        """ Get the settings for the extension """
        from authentikate.settings import get_settings
        # Call the function to get the settings
        settings = get_settings()
        return settings
    
    
    async def aexpand_user_from_token(self, token: JWTToken) -> "UserModel":
        """ Expand a user from the provided JWT token """
        from authentikate.expand import aexpand_user_from_token
        # Call the async function to expand the user
        user = await aexpand_user_from_token(token)
        return cast(UserModel, user)
    
    async def aexpand_client_from_token(self, token: JWTToken) -> "ClientModel":
        """ Expand a client from the provided JWT token """
        from authentikate.expand import aexpand_client_from_token
        # Call the async function to expand the client
        client = await aexpand_client_from_token(token)
        return cast(ClientModel, client)  
    
    async def aexpand_organization_from_token(self, token: JWTToken) -> "OrganizationModel":
        """ Expand an organization from the provided JWT token """
        from authentikate.expand import aexpand_organization_from_token
        # Call the async function to expand the organization
        organization = await aexpand_organization_from_token(token)
        return cast(OrganizationModel, organization)
    
    
    async def aexpand_membership_from_user_and_organization(self, user: UserModel, organization: OrganizationModel, token: JWTToken) -> "MembershipModel":
        """ Expand a membership from the provided JWT token """
        from authentikate.expand import aexpand_membership
        # Call the async function to expand the membership
        membership = await aexpand_membership(user, organization, token)
        return cast(MembershipModel, membership)
        
    
    
    async def on_operation(self) -> Union[AsyncIterator[None], Iterator[None]]:
        """ Set the token in the context variable """
        
        context = self.execution_context.context
        
        reset_user = None
        reset_client = None
        reset_token = None
        reset_organization = None
        
        
        if isinstance(context, WsContext):
            # WebSocket context
            # Do something with the WebSocket context
            
            token = authenticate_token(
                context.connection_params.get("token", ""),
                self.get_settings(),
            )
            reset_token = token_var.set(token)
            if token:
                user = await self.aexpand_user_from_token(token)
                client = await self.aexpand_client_from_token(token)
                organization = await self.aexpand_organization_from_token(token)
                
                
                membership = await self.aexpand_membership_from_user_and_organization(user, organization, token)
                
                reset_client = client_var.set(client)
                reset_user = user_var.set(user)
                reset_organization = organization_var.set(organization)
                
                context.request.set_user(user)  
                context.request.set_client(client)
                context.request.set_membership(membership)
                context.request.set_organization(organization)
                context.request.set_extension("token", token)
                
            
            
        
        elif isinstance(context, HttpContext):
            # HTTP context
            # Do something with the HTTP context
            token = authenticate_header(
                context.headers,
                self.get_settings(),
            )
            reset_token = token_var.set(token)
            if token:
                user = await self.aexpand_user_from_token(token)
                client = await self.aexpand_client_from_token(token)
                organization = await self.aexpand_organization_from_token(token)
                
                membership = await self.aexpand_membership_from_user_and_organization(user, organization, token)
                
                
                reset_client = client_var.set(client)
                reset_user = user_var.set(user)
                reset_organization = organization_var.set(organization)
                
                context.request.set_user(user)  
                context.request.set_client(client)
                context.request.set_membership(membership)
                context.request.set_organization(organization)
                context.request.set_extension("token", token)
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
            
        if reset_organization:
            organization_var.reset(reset_organization)
            
        
        return 
        
       
       

        