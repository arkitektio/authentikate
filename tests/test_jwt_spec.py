from authentikate.base_models import JWTToken
import datetime


def test_jwt_token():

    JWTToken(
        aud="string",
        sub=1,
        iss="lok",
        exp=datetime.datetime.now(),
        roles=["admin"],
        scope="read",
        iat=1,
        jti="string",
        raw="string",
        preferred_username="string",
        client_id="string",
    )


def test_jwt_aud_list():

    JWTToken(
        aud=["string"],
        sub=1,
        iss="lok",
        exp=datetime.datetime.now(),
        roles=["admin"],
        scope="read",
        iat=1,
        jti="string",
        raw="string",
        preferred_username="string",
        client_id="string",
    )


def test_jwt_token_optional():

    JWTToken(
        sub=1,
        iss="lok",
        exp=datetime.datetime.now(),
        roles=["admin"],
        scope="read",
        iat=1,
        jti="string",
        raw="string",
        preferred_username="string",
        client_id="string",
        client_app="karlos",
        client_release="v1",
    )
