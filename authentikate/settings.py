from authentikate.structs import AuthentikateSettings
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import os


cached_settings = None


def prepare_settings() -> AuthentikateSettings:
    try:
        user = settings.AUTH_USER_MODEL
    except AttributeError:
        raise ImproperlyConfigured(
            "AUTH_USER_MODEL must be configured in order to use authentikate"
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
        sub_field = group.get("USER_SUB_FIELD", "sub")
        iss_field = group.get("USER_ISS_FIELD", "iss")
        app_model = group.get("APP_MODEL", "authentikate.App")
        client_id_field = group.get("APP_CLIENT_ID_FIELD", "client_id")
        app_iss_field = group.get("APP_ISS_FIELD", "iss")
        jwt_base_model = group.get("JWT_BASE_MODEL", "authentikate.structs.JWTToken")

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
        sub_field=sub_field,
        iss_field=iss_field,
        app_model=app_model,
        client_id_field=client_id_field,
        app_iss_field=app_iss_field,
        jwt_base_model=jwt_base_model,
    )


def get_settings() -> AuthentikateSettings:
    global cached_settings
    if not cached_settings:
        cached_settings = prepare_settings()
    return cached_settings
