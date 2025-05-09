from authentikate.decode import decode_token
from authentikate.settings import get_settings
from authentikate.base_models import AuthentikateSettings, JWTToken
import re
import logging

logger = logging.getLogger(__name__)  #


def authenticate_token(token: str, settings: AuthentikateSettings) -> JWTToken:
    """
    Authenticate a token and return the auth context
    (containing user, app and scopes)

    """
    decoded: JWTToken

    if token in settings.static_tokens:
        decoded = settings.static_tokens[token]
    else:
        decoded = decode_token(token, settings)

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

    raise ValueError("Not a valid token")


def authenticate_header(
    headers: dict[str, str], settings: AuthentikateSettings | None = None
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
        raise ValueError("No Authorization header")

    token = extract_plain_from_authorization(authorization_header)
    return authenticate_token(token, settings) 
    


def authenticate_header_or_none(
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
        return authenticate_header(headers, settings)
    except Exception:
        logger.error("Error authenticating header. Skipping!", exc_info=True)
        return None


def authenticate_token_or_none(
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
        return authenticate_token(token, settings)
    except Exception:
        logger.error("Error authenticating token. Skipping!", exc_info=True)
        return None




