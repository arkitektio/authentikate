from authentikate.models import User
from authentikate.utils import authenticate_header
from authentikate.base_models import AuthentikateSettings
from guardian.shortcuts import assign_perm
from authentikate.base_models import StaticToken


def test_static_token(db, key_pair_str):
    user_one = User.objects.create_user(
        username="testuser",
        email="nana",
    )
    user_one.sub = "1"
    user_one.iss = "XXXX"
    user_one.save()

    
    fake_token = "osins"

    headers = {"Authorization": f"Bearer {fake_token}"}

    settings = AuthentikateSettings(
        algorithms=["RS256"],
        public_key=key_pair_str.public_key,
        allow_imitate=True,
        force_client=False,
        static_tokens={fake_token: StaticToken(sub="1", iss="XXXX")},
    )

    x = authenticate_header(headers, settings)
    assert x.sub == "1", "User ID should be 1"
    assert x.iss == "XXXX", "Issuer should be 'XXXX'"




