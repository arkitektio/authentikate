from authentikate.decode import adecode_token
from authentikate.settings import get_settings
from authentikate.base_models import AuthentikateSettings, JWTToken
from authentikate.errors import (
    AuthentikatePermissionDenied,
    AuthentikateTokenExpired,
    JwksError,
    NoAuthorizationHeader,
    MalformedAuthorizationHeader,
    OrganizationNotAllowed,
)
import datetime
import re
import logging

logger = logging.getLogger(__name__)  #


def _check_organization_allowed(
    decoded: JWTToken, settings: AuthentikateSettings
) -> None:
    """Reject a token naming an organization this service does not accept.

    Organizations are auto-created from the ``active_org`` claim further down
    the expansion path, so without an allow-list every distinct value the issuer
    emits creates rows. Checked here, at the single authentication funnel, so it
    applies to static and signed tokens alike and runs before any database
    write. Unset (the default) keeps the previous accept-anything behaviour.
    """
    allowed = settings.allowed_organizations
    if allowed is None:
        return

    if decoded.active_org not in allowed:
        raise OrganizationNotAllowed(
            f"Organization {decoded.active_org!r} is not accepted by this service"
        )


async def authenticate_token(token: str, settings: AuthentikateSettings) -> JWTToken:
    """
    Authenticate a token and return the auth context
    (containing user, app and scopes)

    """
    decoded: JWTToken

    if token in settings.static_tokens:
        decoded = settings.static_tokens[token]
        # Static tokens skip signature verification by design, but their
        # configured expiry must still be honoured -- otherwise a short-lived
        # static token would silently never expire.
        if decoded.exp <= datetime.datetime.now(datetime.timezone.utc):
            raise AuthentikateTokenExpired("Static token has expired")
    else:
        decoded = await adecode_token(token, settings)

    _check_organization_allowed(decoded, settings)

    return decoded


jwt_re = re.compile(r"Bearer\s(?P<token>[^\s]*)")


def extract_plain_from_authorization(authorization: str) -> str:
    """
    Extract a plain token from an Authorization header

    Parameters
    ----------

    authorization : str
        The Authorization header

    Returns
    -------
    str
        The token
    """

    m = jwt_re.match(authorization)
    if m:
        token = m.group("token")
        return token

    raise MalformedAuthorizationHeader("Not a valid token")


async def authenticate_header(
    headers: dict[str, str],
    settings: AuthentikateSettings | None = None,
) -> JWTToken:
    """
    Authenticate a request and return the auth context
    (containing user, app and scopes)

    """
    if not settings:
        settings = get_settings()

    authorization_header = None

    for i in settings.authorization_headers:
        authorization_header = headers.get(i, None)
        if authorization_header:
            break

    if not authorization_header:
        raise NoAuthorizationHeader("No Authorization header")

    token = await authenticate_token(
        extract_plain_from_authorization(authorization_header), settings
    )

    return token


async def authenticate_header_or_none(
    headers: dict[str, str], settings: AuthentikateSettings | None = None
) -> JWTToken | None:
    """
    Authenticate a request header and return the auth context

    Parameters
    ----------
    headers : dict
        The headers to authenticate

    settings : AuthentikateSettings, optional
        The settings to use, by default None

    Returns
    -------
    Auth | None
        The auth context or None if the token is invalid


    """
    try:
        return await authenticate_header(headers, settings)
    except AuthentikatePermissionDenied:
        return None
    except JwksError:
        # Key retrieval failed (issuer unreachable, malformed JWKS). That is an
        # infrastructure fault, not a permission decision, but it must not
        # escape as an unhandled 500 either -- treat it as "not authenticated".
        logger.warning("Could not retrieve JWKS to verify token", exc_info=True)
        return None


async def authenticate_token_or_none(
    token: str, settings: AuthentikateSettings | None = None
) -> JWTToken | None:
    """
    Authenticate a token and return the auth context

    Tries to authenticate the token, if it fails it will return None


    Parameters
    ----------
    token : str
        The token to authenticate

    settings : AuthentikateSettings, optional
        The settings to use, by default None

    Returns
    -------
    Auth | None
        The auth context or None if the token is invalid


    """

    if not settings:
        settings = get_settings()

    try:
        return await authenticate_token(token, settings)
    except AuthentikatePermissionDenied:
        logger.debug("Token authentication failed", exc_info=True)
        return None
    except JwksError:
        logger.warning("Could not retrieve JWKS to verify token", exc_info=True)
        return None
