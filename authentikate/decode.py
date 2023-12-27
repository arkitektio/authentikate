import jwt
from authentikate import errors, structs


def decode_token(token: str, algorithms: list, public_key: str) -> structs.JWTToken:
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
        decoded = jwt.decode(token, public_key, algorithms=algorithms)
    except Exception as e:
        raise errors.InvalidJwtTokenError("Error decoding token") from e

    try:
        return structs.JWTToken(**decoded)
    except TypeError as e:
        raise errors.MalformedJwtTokenError("Error decoding token") from e
