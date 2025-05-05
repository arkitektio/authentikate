from authentikate.models import User
from authentikate.expand import expand_token
from authentikate.decode import decode_token
from authentikate.utils import authenticate_header, authenticate_header_or_none
from authentikate.base_models import AuthentikateSettings
from guardian.shortcuts import assign_perm


def test_imitate(db, valid_jwt, key_pair_str):
    user_one = User.objects.create_user(
        username="testuser",
        email="nana",
    )
    user_one.sub = "1"
    user_one.iss = "XXXX"
    user_one.save()

    user_two = User.objects.create_user(
        username="testuser2",
        email="nana",
    )
    user_two.sub = "2"
    user_two.iss = "XXXX"
    user_two.save()

    assign_perm("authentikate.imitate", user_one, user_two)

    headers = {"Authorization": f"Bearer {valid_jwt}", "X-Imitate-User": "2@XXXX"}

    settings = AuthentikateSettings(
        algorithms=["RS256"],
        public_key=key_pair_str.public_key,
        allow_imitate=True,
        force_client=False,
    )

    x = authenticate_header(headers, settings)
    assert x.user.sub == "2", "User ID should be 2"
    assert x.client.client_id == "XXXX", "Client ID should be 'static'"
