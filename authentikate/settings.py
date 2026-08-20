import logging
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from authentikate.base_models import ANY_AUDIENCE, AuthentikateSettings
from typing import Optional
from pydantic import ValidationError

logger = logging.getLogger(__name__)

cached_settings: Optional[AuthentikateSettings] = None


def _check_deployment_safety(parsed: AuthentikateSettings) -> None:
    """Reject or warn about settings that are unsafe outside development.

    Raises
    ------
    ImproperlyConfigured
        When static tokens -- which bypass signature verification entirely --
        are configured while ``DEBUG`` is False.
    """

    if parsed.static_tokens and not settings.DEBUG:
        if not parsed.allow_static_tokens_in_production:
            raise ImproperlyConfigured(
                "AUTHENTIKATE.STATIC_TOKENS is set while DEBUG is False. Static "
                "tokens bypass signature verification and are for tests only. "
                "Remove them, or set ALLOW_STATIC_TOKENS_IN_PRODUCTION if this "
                "is deliberate."
            )
        logger.warning(
            "AUTHENTIKATE.STATIC_TOKENS is enabled with DEBUG=False via "
            "ALLOW_STATIC_TOKENS_IN_PRODUCTION. These tokens bypass signature "
            "verification."
        )

    if parsed.audience is None:
        logger.warning(
            "AUTHENTIKATE.AUDIENCE is not set, so the 'aud' claim is not "
            "checked: a token this issuer minted for any other service is "
            "accepted here. Set it to this service's identifier, or to '*' to "
            "accept any audience deliberately. This will become required in "
            "authentikate 4.0."
        )
    elif parsed.audience == ANY_AUDIENCE:
        # Deliberate, but the posture is the same as leaving it unset, so an
        # operator reading the logs should still be able to see it.
        logger.warning(
            "AUTHENTIKATE.AUDIENCE is '*', so the 'aud' claim is not checked: "
            "a token this issuer minted for any other service is accepted here."
        )


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
        parsed = AuthentikateSettings(**group)

    except ValidationError as e:
        raise ImproperlyConfigured(
            "Invalid settings for AUTHENTIKATE. Please check your settings."
        ) from e

    _check_deployment_safety(parsed)
    return parsed


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
