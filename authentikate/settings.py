from authentikate.structs import AuthentikateSettings
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import os


cached_settings = None


def prepare_settings() -> AuthentikateSettings:
    """Prepare the settings

    Prepare the settings for authentikate from django_settings.
    This function will raise a ImproperlyConfigured exception if the settings are
    not correct.

    Returns
    -------
    AuthentikateSettings
        The settings

    Raises
    ------
    ImproperlyConfigured
        When the settings are not correct
    """


    try:
        user = settings.AUTH_USER_MODEL
        if user != "authentikate.User":
            raise ImproperlyConfigured(
                "AUTH_USER_MODEL must be authentikate.User in order to use authentikate"
            )
    except AttributeError:
        raise ImproperlyConfigured(
            "AUTH_USER_MODEL must be authentikate.User in order to use authentikate"
        )

    try:
        group = settings.AUTHENTIKATE
    except AttributeError:
        raise ImproperlyConfigured("Missing setting AUTHENTIKATE")

    try:
        algorithms = [group["KEY_TYPE"]]

        public_key = group.get("PUBLIC_KEY", None)
        allow_imitate = group.get("ALLOW_IMITATE", True)
        imitation_headers = group.get("IMITATION_HEADERS", None)
        imitate_permission = group.get("IMITATE_PERMISSION", None)
        authorization_headers = group.get("AUTHORIZATION_HEADERS", None)

        if not public_key:
            pem_file = group.get("PUBLIC_KEY_PEM_FILE", None)
            if not pem_file:
                raise ImproperlyConfigured(
                    "Missing setting in AUTHENTIKAE: PUBLIC_KEY_PEM_FILE (path to public_key.pem) or PUBLIC_KEY (string of public key)"
                )

            try:
                base_dir = settings.BASE_DIR
            except AttributeError:
                raise ImproperlyConfigured("Missing setting AUTHENTIKATE")

            try:
                path = os.path.join(base_dir, pem_file)

                with open(path, "rb") as f:
                    public_key = f.read()

            except FileNotFoundError:
                raise ImproperlyConfigured(f"Pem File not found: {path}")

        force_client = group.get("FORCE_CLIENT", False)

    except KeyError:
        raise ImproperlyConfigured(
            "Missing setting AUTHENTIKATE KEY_TYPE or AUTHENTIKATE PUBLIC_KEY"
        )

    return AuthentikateSettings(
        algorithms=algorithms,
        public_key=public_key,
        force_client=force_client,
        imitation_headers=imitation_headers,
        authorization_headers=authorization_headers,
        allow_imitate=allow_imitate,
        imitate_permission=imitate_permission,
    )


def get_settings() -> AuthentikateSettings:
    """Get the settings

    Returns
    -------

    AuthentikateSettings
        The settings
    """
    global cached_settings
    if not cached_settings:
        cached_settings = prepare_settings()
    return cached_settings
