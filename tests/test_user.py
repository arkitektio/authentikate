from authentikate.models import User


def test_create_user(db: None) -> None:
    User.objects.create_user(
        username="testuser",
        email="nana",
    )
