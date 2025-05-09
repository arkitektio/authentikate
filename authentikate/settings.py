from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import os
from authentikate.base_models import AuthentikateSettings
from typing import Optional
from pydantic import ValidationError

cached_settings: Optional[AuthentikateSettings] = None


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

        return AuthentikateSettings(
            **group
        )

    except ValidationError as e:
        raise ImproperlyConfigured(
            "Invalid settings for AUTHENTIKATE. Please check your settings."
        ) from e


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
