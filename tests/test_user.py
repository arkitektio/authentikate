from authentikate.models import User


def test_create_user(db):
    user = User.objects.create_user(
        username="testuser",
        email="nana",
    )
