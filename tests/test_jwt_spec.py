import datetime

import pytest
from pydantic import ValidationError

from authentikate.base_models import JWTToken


def test_jwt_token() -> None:

    JWTToken(
        aud="string",
        sub=1,
        iss="lok",
        exp=datetime.datetime.now(datetime.UTC),
        roles=["admin"],
        scope="read",
        iat=1,
        jti="string",
        raw="string",
        preferred_username="string",
        client_id="string",
    )


def test_jwt_aud_list() -> None:

    JWTToken(
        aud=["string"],
        sub=1,
        iss="lok",
        exp=datetime.datetime.now(datetime.UTC),
        roles=["admin"],
        scope="read",
        iat=1,
        jti="string",
        raw="string",
        preferred_username="string",
        client_id="string",
    )


def test_jwt_token_optional() -> None:

    JWTToken(
        aud="string",
        sub=1,
        iss="lok",
        exp=datetime.datetime.now(datetime.UTC),
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


def test_jwt_aud_is_required() -> None:
    """A token that names no audience is scoped to no service."""

    with pytest.raises(ValidationError):
        JWTToken(
            sub=1,
            iss="lok",
            exp=datetime.datetime.now(datetime.UTC),
            roles=["admin"],
            scope="read",
            iat=1,
            jti="string",
            raw="string",
            preferred_username="string",
            client_id="string",
        )
