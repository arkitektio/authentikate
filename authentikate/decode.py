from joserfc import jwt
from authentikate import base_models, errors


def decode_token(
    token: str,  settings: base_models.AuthentikateSettings
) -> base_models.JWTToken:
    """Decode a JWT token

    Parameters
    ----------
    token : str
        The token to decode
    algorithms : list
        The algorithms to use to decode the token
    public_key : str
        The public key to use to decode the token

    Returns
    -------
    structs.JWTToken
        The decoded token
    """
    try:
        decoded = jwt.decode(token, settings.load_key)
    except Exception as e:
        raise errors.InvalidJwtTokenError("Error decoding token") from e

    try:
        return base_models.JWTToken(**{"raw": token, **decoded.claims})
    except TypeError as e:
        raise errors.MalformedJwtTokenError("Error decoding token") from e
