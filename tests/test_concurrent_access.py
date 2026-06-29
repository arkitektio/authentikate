"""Tests for concurrent authentication / race conditions.

Two requests authenticating the *same* not-yet-existing token at once used to
race in ``expand_user_from_token`` / ``aexpand_user_from_token``: both passed
the ``get`` lookup, both attempted an ``INSERT``, and the loser hit the
``(sub, iss)`` unique constraint with an ``IntegrityError`` ("cannot create
because it exists"). The fix makes the create branch recover by re-fetching the
winner's row.

Note on reproducing the race: the suite runs on in-memory SQLite, and Django's
async ORM runs on a separate connection from pytest-django's test transaction,
so a real duplicate ``asave()`` silently succeeds rather than raising — the DB
constraint is not enforced across the test-transaction boundary. The race is
therefore reproduced *deterministically* at the application seam: the initial
lookup is forced to miss, and ``save`` is forced to raise ``IntegrityError``
(exactly what the database would do when a concurrent request committed first).
This directly exercises the recovery branch the fix adds.
"""

from unittest.mock import patch

import pytest
from django.db import IntegrityError, transaction

from authentikate.decode import decode_token
from authentikate.expand import (
    aexpand_token_context,
    aexpand_user_from_token,
    expand_user_from_token,
)
from authentikate.models import App, Client, Membership, Organization, Release, User


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
async def test_aexpand_user_recovers_from_concurrent_create(valid_jwt, valid_settings):
    """A lost create race must re-fetch the existing user, not raise.

    Uses ``transaction=True`` because async ORM writes run on a connection
    outside pytest-django's rollback, so the table must be flushed between tests
    to keep this test's rows from leaking into others.
    """
    token = decode_token(valid_jwt, valid_settings)

    # First authentication creates the user normally.
    first = await aexpand_user_from_token(token)

    # Simulate a second concurrent request: its initial lookup misses, so it
    # enters the create branch; the INSERT then loses to the request that
    # already committed (asave -> IntegrityError). The fix must recover by
    # re-fetching the existing row instead of propagating the error.
    real_aget = User.objects.aget
    aget_calls = {"n": 0}

    async def flaky_aget(*args, **kwargs):
        aget_calls["n"] += 1
        if aget_calls["n"] == 1:
            raise User.DoesNotExist
        return await real_aget(*args, **kwargs)

    async def losing_asave(self, *args, **kwargs):
        raise IntegrityError("UNIQUE constraint failed: authentikate_user.sub")

    with patch.object(User.objects, "aget", side_effect=flaky_aget), patch.object(
        User, "asave", new=losing_asave
    ):
        second = await aexpand_user_from_token(token)

    assert second.pk == first.pk
    assert second.sub == token.sub
    # Exactly one row for this identity (a separate guardian AnonymousUser also
    # exists in the table, so scope the count to the token's sub/iss).
    assert await User.objects.filter(sub=token.sub, iss=token.iss).acount() == 1


def test_expand_user_recovers_from_concurrent_create(db, valid_jwt, valid_settings):
    """Sync mirror of the recovery test."""
    token = decode_token(valid_jwt, valid_settings)

    first = expand_user_from_token(token)

    real_get = User.objects.get
    get_calls = {"n": 0}

    def flaky_get(*args, **kwargs):
        get_calls["n"] += 1
        if get_calls["n"] == 1:
            raise User.DoesNotExist
        return real_get(*args, **kwargs)

    def losing_save(self, *args, **kwargs):
        raise IntegrityError("UNIQUE constraint failed: authentikate_user.sub")

    with patch.object(User.objects, "get", side_effect=flaky_get), patch.object(
        User, "save", new=losing_save
    ):
        second = expand_user_from_token(token)

    assert second.pk == first.pk
    assert second.sub == token.sub
    assert User.objects.filter(sub=token.sub, iss=token.iss).count() == 1


@pytest.mark.asyncio
@pytest.mark.django_db(transaction=True)
async def test_repeated_token_expansion_is_idempotent(valid_jwt, valid_settings):
    """Re-authenticating the same token must not duplicate any related rows.

    This guards the ``get_or_create`` / ``update_or_create`` paths for the
    organization, client, app, release and membership: repeated expansion of one
    token converges to a single row per model. (App/Release rely on the unique
    constraints added alongside this change.)
    """
    token = decode_token(valid_jwt, valid_settings)

    first = await aexpand_token_context(token)
    second = await aexpand_token_context(token)

    assert first.user.pk == second.user.pk
    assert first.organization.pk == second.organization.pk
    assert first.client.pk == second.client.pk

    # Scope the user count to the token identity (guardian adds an AnonymousUser).
    assert await User.objects.filter(sub=token.sub, iss=token.iss).acount() == 1
    assert await Organization.objects.acount() == 1
    assert await Membership.objects.acount() == 1
    assert await Client.objects.acount() == 1
    assert await App.objects.acount() == 1
    assert await Release.objects.acount() == 1


def test_app_identifier_is_unique(db):
    """App.identifier must be unique so concurrent get_or_create cannot duplicate."""
    App.objects.create(identifier="my_app")
    # Wrap the expected failure in atomic() so the broken statement is rolled
    # back to a savepoint and the surrounding test transaction stays usable.
    with pytest.raises(IntegrityError), transaction.atomic():
        App.objects.create(identifier="my_app")


def test_release_app_version_is_unique(db):
    """Release must be unique per (app, version)."""
    app = App.objects.create(identifier="my_app")
    Release.objects.create(app=app, version="v1.0.0")
    with pytest.raises(IntegrityError), transaction.atomic():
        Release.objects.create(app=app, version="v1.0.0")
