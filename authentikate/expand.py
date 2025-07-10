from django.contrib.auth.models import Group
from authentikate import base_models, models
import logging
from django.contrib.auth import get_user_model


logger = logging.getLogger(__name__)


def token_to_username(token: base_models.JWTToken) -> str:
    """Convert a JWT token to a username

    Parameters
    ----------
    token : structs.JWTToken
        The token to convert

    Returns
    -------

    str
        The username



    """
    return f"{token.iss}_{token.sub}"





async def aset_user_groups(user: models.User, roles: list[str]) -> None:
    """Add a list of roles to a user

    Roles are added as groups

    Parameters
    ----------
    user : models.User
        The user to add the roles to
    roles : list[str]
        The roles to add
    """
    for role in roles:
        g, _ = await Group.objects.aget_or_create(name=role)
        await user.groups.aadd(g)


def set_user_groups(user: models.User, roles: list[str]) -> None:
    """Add a list of roles to a user

    Roles are added as groups

    Parameters
    ----------
    user : models.User
        The user to add the roles to
    roles : list[str]
        The roles to add
    """
    for role in roles:
        g, _ = Group.objects.get_or_create(name=role)
        user.groups.add(g)



async def aexpand_user_from_token(
    token: base_models.JWTToken,
) -> models.User:
    """
    Expand a user from the provided JWT token.
    """
    
    try:
        user = await models.User.objects.aget(sub=token.sub, iss=token.iss)
        if user.changed_hash != token.changed_hash:
            # User has changed, update the user object
            user.first_name = token.preferred_username
            user.changed_hash = token.changed_hash
            
            if token.active_org:
                current_org, _ = await models.Organization.objects.aget_or_create(
                    identifier=token.active_org or "",
                )
                
                user.active_organization = current_org
                
            user.active_organization = current_org
            
            
            await user.asave()
            await aset_user_groups(user, token.roles)
            
            
        return user

    except models.User.DoesNotExist:

        user = models.User(
            sub=token.sub,
            username=token_to_username(token),
            iss=token.iss,
            first_name=token.preferred_username,
        )
        user.set_unusable_password()
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash
        
        if token.active_org:
            current_org, _ = await models.Organization.objects.aget_or_create(
                identifier=token.active_org or "",
            )
            
            user.active_organization = current_org
        
        await user.asave()
        await aset_user_groups(user, token.roles)
        return user
   
def expand_user_from_token(
    token: base_models.JWTToken,
) -> models.User:
    """
    Expand a user from the provided JWT token.
    """
    
    try:
        user = models.User.objects.get(sub=token.sub, iss=token.iss)
        if user.changed_hash != token.changed_hash:
            # User has changed, update the user object
            user.first_name = token.preferred_username
            user.changed_hash = token.changed_hash
            set_user_groups(user, token.roles)
            
            if token.active_org:
                current_org, _ = models.Organization.objects.get_or_create(
                    identifier=token.active_org)
                
                user.active_organization = current_org
            
            user.save()
            
        return user

    except models.User.DoesNotExist:
        preexisting_user = models.User.objects.filter(
            username=token.preferred_username
        ).first()

        user = models.User(
            sub=token.sub,
            username=token_to_username(token)
            if preexisting_user
            else token.preferred_username,
            iss=token.iss,
            first_name=token.preferred_username,
        )
        user.set_unusable_password()
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash
        
        if token.active_org:
            current_org, _ = models.Organization.objects.get_or_create(
                identifier=token.active_org)
            
            user.active_organization = current_org
        
        
        user.save()
        set_user_groups(user, token.roles)
        return user 
    
async def aexpand_client_from_token(
    token: base_models.JWTToken,
) -> models.Client:
    """
    Expand a client from the provided JWT token.
    """
    client, _ = await models.Client.objects.aget_or_create(
        client_id=token.client_id, iss=token.iss
    )
    return client


def expand_client_from_token(
    token: base_models.JWTToken,
) -> models.Client:
    """
    Expand a client from the provided JWT token.
    """
    client, _ = models.Client.objects.get_or_create(
        client_id=token.client_id, iss=token.iss
    )
    return client



