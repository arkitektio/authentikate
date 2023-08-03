from authentikate.models import User
from authentikate.decode import decode_token
import jwt


def test_create_user(db):
    user = User.objects.create_user(
        username="testuser",
        email="nana",
    )
