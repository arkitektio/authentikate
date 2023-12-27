from authentikate.models import User
from authentikate.expand import expand_token
from authentikate.decode import decode_token
from authentikate.utils import authenticate_header
from authentikate.structs import AuthentikateSettings
from guardian.shortcuts import assign_perm
from authentikate.structs import StaticToken


def test_static_token(db, key_pair_str):
    fake_token = "osins"

    headers = {"Authorization": f"Bearer {fake_token}", "X-Imitate-User": "2@XXXX"}

    settings = AuthentikateSettings(
        algorithms=["RS256"],
        public_key=key_pair_str.public_key,
        allow_imitate=True,
        force_client=False,
        static_tokens={fake_token: StaticToken(sub="1")},
    )

    x = authenticate_header(headers, settings)
    assert x.user.sub == "1", "User ID should be 1"
