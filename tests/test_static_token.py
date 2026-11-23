import asyncio

from authentikate.base_models import AuthentikateSettings, StaticToken
from authentikate.models import User
from authentikate.utils import authenticate_header
from tests.conftest import KeyPairStr


def test_static_token(db: None, key_pair_str: KeyPairStr) -> None:
    static_sub = "static-user"
    static_iss = "static-issuer"

    user_one = User.objects.create_user(
        username="testuser",
        email="nana",
    )
    user_one.sub = static_sub
    user_one.iss = static_iss
    user_one.save()

    fake_token = "osins"

    headers = {"Authorization": f"Bearer {fake_token}"}

    settings = AuthentikateSettings(
        audience="*",
        issuers=[],
        static_tokens={fake_token: StaticToken(sub=static_sub, iss=static_iss)},
    )

    x = asyncio.run(authenticate_header(headers, settings))
    assert x.sub == static_sub, "User ID should match the static token"
    assert x.iss == static_iss, "Issuer should match the static token"
    assert x.org == "static_org", "Active organization should be 'static_org'"
