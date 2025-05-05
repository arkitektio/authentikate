from authentikate.base_models import Auth
from authentikate.decode import decode_token
from authentikate.settings import get_settings
from authentikate.base_models import AuthentikateSettings, JWTToken
import re
import logging
from authentikate.expand import expand_token
from authentikate.imitate import imitate_user

logger = logging.getLogger(__name__)  #


def authenticate_token(token: str, settings: AuthentikateSettings) -> Auth:
    """
    Authenticate a token and return the auth context
    (containing user, app and scopes)

    """
    decoded: JWTToken

    if token in settings.static_tokens:
        decoded = settings.static_tokens[token]
    else:
        decoded = decode_token(token, settings.algorithms, settings.public_key)

    return expand_token(decoded, settings.force_client)


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

    raise ValueError("Not a valid token")


def authenticate_header(
    headers: dict[str, str], settings: AuthentikateSettings | None = None
) -> Auth:
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
        raise ValueError("No Authorization header")

    token = extract_plain_from_authorization(authorization_header)
    
    auth = authenticate_token(token, settings)
    
    if settings.allow_imitate:
        imitate_header = None
        
        for i in settings.imitate_headers:
            imitate_header = headers.get(i, None)
            if imitate_header:
                break

        if imitate_header:
            return imitate_user(auth, imitate_header, settings)
        else:
            logger.info("Imitation header not found. User acts on their own behalf!")
    else:
        logger.info("Imitation is not allowed. Skipping!")

    return auth


def authenticate_header_or_none(
    headers: dict[str, str], settings: AuthentikateSettings | None = None
) -> Auth | None:
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
        return authenticate_header(headers, settings)
    except Exception:
        logger.error("Error authenticating header. Skipping!", exc_info=True)
        return None


def authenticate_token_or_none(
    token: str, settings: AuthentikateSettings | None = None
) -> Auth | None:
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
        return authenticate_token(token, settings)
    except Exception:
        logger.error("Error authenticating token. Skipping!", exc_info=True)
        return None
