from authentikate.errors import AuthentikatePermissionDenied
import time
from django.contrib.auth.models import Group
from authentikate import models, structs
import logging


logger = logging.getLogger(__name__)


def token_to_username(token: structs.JWTToken):
    """Convert a JWT token to a username"""
    return f"{token.iss}_{token.sub}"


def set_user_groups(user: models.User, roles: list[str]):
    """Set the groups of a user"""
    for role in roles:
        g, _ = Group.objects.get_or_create(name=role)
        user.groups.add(g)


def get_app(
    token: structs.JWTToken, settings: structs.AuthentikateSettings
) -> models.App:
    """Get or create an app"""
    app, _ = models.App.objects.get_or_create(
        **{settings.client_id_field: token.client_id, settings.app_iss_field: token.iss}
    )
    return app


def get_user(
    token: structs.JWTToken, settings: structs.AuthentikateSettings
) -> models.User:
    return models.User.objects.get(
        **{settings.sub_field: token.sub, settings.iss_field: token.iss}
    )


def expand_token(
    token: structs.JWTToken, settings: structs.AuthentikateSettings
) -> structs.Auth:
    if token.sub is None:
        raise AuthentikatePermissionDenied("Missing sub parameter in JWT token")

    if token.iss is None:
        raise AuthentikatePermissionDenied("Missing iss parameter in JWT token")

    if token.exp is None:
        raise AuthentikatePermissionDenied("Missing exp parameter in JWT token")

    # Check if token is expired
    if token.exp < time.time():
        raise AuthentikatePermissionDenied("Token has expired")

    if token.client_id is None:
        if settings.force_client:
            raise AuthentikatePermissionDenied(
                "Missing client_id parameter in JWT token"
            )

    try:
        if token.client_id is None:
            app = None
        else:
            app = get_app(token, settings)

        user = models.User.objects.get(sub=token.sub, iss=token.iss)
        if user.changed_hash != token.changed_hash:
            # User has changed, update the user object
            user.first_name = token.preferred_username
            user.changed_hash = token.changed_hash
            set_user_groups(user, token.roles)
            user.save()

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
        user.save()
        user.first_name = token.preferred_username
        user.changed_hash = token.changed_hash
        set_user_groups(user, token.roles)
        user.save()
    except Exception as e:
        logger.error(f"Error while authenticating: {e}", exc_info=True)
        raise AuthentikatePermissionDenied(f"Error while authenticating: {e}")

    return structs.Auth(
        token=token,
        user=user,
        app=app,
    )
