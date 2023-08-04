from authentikate.structs import Auth, AuthentikateSettings
from authentikate.models import User


def imitate_user(auth: Auth, imitate_id: str, settings: AuthentikateSettings) -> Auth:
    sub, iss = imitate_id.split("@")
    user = User.objects.get(sub=sub, iss=iss)

    if auth.user.has_perm(settings.imitate_permission, user):
        auth.user = user
        return auth

    else:
        raise PermissionError("User does not have permission to imitate this user")
