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

    if parsed.audience == ANY_AUDIENCE:
        # Deliberate -- AUDIENCE is required, so nobody lands here by omission --
        # but a token minted for another service is still accepted, so an
        # operator reading the logs should be able to see it.
        logger.warning(
            "AUTHENTIKATE.AUDIENCE is '*', so the 'aud' claim is required but "
            "not matched: a token this issuer minted for any other service is "
            "accepted here."
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
        # Name the offending keys: this is raised at startup, to the operator
        # who wrote the settings, so "check your settings" alone left the most
        # common upgrade failure (a missing AUDIENCE) as a mystery crash. The
        # values are operator-supplied configuration, not attacker-supplied
        # request data, so there is nothing here to withhold.
        problems = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or 'AUTHENTIKATE'}: "
            f"{error['msg']}"
            for error in e.errors()
        )
        raise ImproperlyConfigured(
            f"Invalid settings for AUTHENTIKATE -- {problems}"
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
