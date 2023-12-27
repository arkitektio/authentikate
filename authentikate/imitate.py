from authentikate.structs import Auth, AuthentikateSettings
from authentikate.models import User


def imitate_user(auth: Auth, imitate_id: str, settings: AuthentikateSettings) -> Auth:
    """Imitate a user

    Parameters
    ----------
    auth : Auth
        The auth context to imitate

    imitate_id : str
        The user to imitate needs to folow the format sub@iss

    settings : AuthentikateSettings
        The settings to use

    Returns
    -------
    Auth
        The new auth context
    """


    sub, iss = imitate_id.split("@")
    user = User.objects.get(sub=sub, iss=iss)

    if auth.user.has_perm(settings.imitate_permission, user):
        auth.user = user
        return auth

    else:
        raise PermissionError("User does not have permission to imitate this user")
