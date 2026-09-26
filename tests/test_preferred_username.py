"""The token's profile claims live in real ``User`` columns, so downstream services can expose them.

Before 0007 the ``preferred_username`` claim was stored on Django's ``first_name``, and services
declaring their own narrow ``User`` type (mikro, bank) with a plain ``preferred_username: str``
failed with "'User' object has no attribute 'preferred_username'". These tests pin that a plain
declaration works — also under the query optimizer in an async resolver, where a deferred
column would otherwise need a synchronous query — and that the optional OIDC profile claims
are mirrored (and cleared when no longer sent).
"""

import pytest
import strawberry
import strawberry_django
from asgiref.sync import sync_to_async
from strawberry_django.optimizer import DjangoOptimizerExtension

from authentikate import models


@strawberry_django.type(models.User)
class NarrowUser:
    """What a downstream service declares: no field_name mapping."""

    id: strawberry.ID
    preferred_username: str


@strawberry_django.type(models.Membership)
class NarrowMembership:
    id: strawberry.ID
    user: NarrowUser


@strawberry.type
class Query:
    users: list[NarrowUser] = strawberry_django.field()
    memberships: list[NarrowMembership] = strawberry_django.field()


schema = strawberry.Schema(query=Query, extensions=[DjangoOptimizerExtension])


def _seed() -> None:
    org = models.Organization.objects.create(slug="acme")
    user = models.User.objects.create(username="u-1", sub="1", iss="iss", preferred_username="alice")
    models.Membership.objects.create(user=user, organization=org)


def test_model_exposes_preferred_username(db):
    user = models.User(username="u-1", preferred_username="alice")
    assert user.preferred_username == "alice"


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
async def test_narrow_type_resolves_preferred_username_under_the_optimizer():
    await sync_to_async(_seed)()

    result = await schema.execute("{ users { preferredUsername } memberships { user { preferredUsername } } }")

    assert result.errors is None, result.errors
    assert {"preferredUsername": "alice"} in result.data["users"]
    assert result.data["memberships"] == [{"user": {"preferredUsername": "alice"}}]


def _token(**claims):
    from authentikate.base_models import JWTToken

    base = {
        "sub": "7",
        "iss": "https://issuer.test",
        "exp": 4102444800,
        "iat": 1700000000,
        "client_id": "c",
        "preferred_username": "alice",
        "roles": [],
        "scope": "openid profile email",
        "aud": ["svc"],
        "raw": "x",
    }
    return JWTToken(**{**base, **claims})


def test_profile_claims_are_mirrored_and_cleared(db):
    from authentikate.expand import _expand_user

    full = _token(
        name="Alice Liddell",
        given_name="Alice",
        family_name="Liddell",
        nickname="al",
        email="alice@example.test",
        email_verified=True,
        picture="https://example.test/alice.png",
        locale="de-AT",
        zoneinfo="Europe/Vienna",
    )
    user = _expand_user(full)
    user.refresh_from_db()
    assert (user.preferred_username, user.name, user.first_name, user.last_name, user.nickname) == ("alice", "Alice Liddell", "Alice", "Liddell", "al")
    assert (user.email, user.email_verified, user.picture, user.locale, user.zoneinfo) == ("alice@example.test", True, "https://example.test/alice.png", "de-AT", "Europe/Vienna")

    # The issuer stops sending the optional claims (e.g. a narrower scope): they are cleared.
    user = _expand_user(_token(preferred_username="alice2"))
    user.refresh_from_db()
    assert (user.preferred_username, user.name, user.first_name, user.email, user.picture) == ("alice2", None, "", "", None)


def test_profile_changes_alone_trigger_a_resync():
    assert _token().changed_hash != _token(name="Alice").changed_hash
    assert _token(name="Alice").changed_hash == _token(name="Alice").changed_hash


@pytest.mark.django_db(transaction=True)
def test_migration_moves_the_username_off_first_name():
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    before, after = [("authentikate", "0006_alter_app_identifier_alter_release_unique_together")], [("authentikate", "0007_user_profile")]
    executor = MigrationExecutor(connection)
    executor.migrate(before)
    OldUser = executor.loader.project_state(before).apps.get_model("authentikate", "User")
    OldUser.objects.create(username="legacy", sub="9", iss="iss", first_name="jhnnsrs", changed_hash="old")

    executor = MigrationExecutor(connection)
    executor.loader.build_graph()
    executor.migrate(after)

    user = models.User.objects.get(sub="9")
    assert (user.preferred_username, user.first_name, user.changed_hash) == ("jhnnsrs", "", None)
