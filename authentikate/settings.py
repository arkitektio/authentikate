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
