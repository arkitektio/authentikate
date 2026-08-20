import datetime
from types import SimpleNamespace

import pytest
import strawberry
from graphql import GraphQLError
from joserfc import jwt
from joserfc.jwk import RSAKey

from authentikate.base_models import JWTToken
from authentikate.decode import adecode_token, decode_token
from authentikate.errors import AuthentikateTokenExpired, MalformedJwtTokenError
from django.contrib.auth.models import Group

from authentikate.expand import (
    aexpand_token_context,
    aexpand_user_from_token,
    expand_user_from_token,
)
from authentikate.models import Organization, User
from authentikate.strawberry.directives import AuthExtension
from authentikate.strawberry.types import User as UserType


@pytest.fixture(scope="session")
def expired_jwt(valid_claims, key_pair_str):
    key = RSAKey.import_key(key_pair_str.private_key)
    claims = {
        **valid_claims,
        "iat": int(
            (datetime.datetime.now() - datetime.timedelta(days=2)).timestamp()
        ),
        "exp": int(
            (datetime.datetime.now() - datetime.timedelta(days=1)).timestamp()
        ),
    }
    return jwt.encode({"alg": "RS256", "kid": "1"}, claims, key)


def test_decode_token_rejects_expired(expired_jwt, valid_settings):
    with pytest.raises(AuthentikateTokenExpired):
        decode_token(expired_jwt, valid_settings)


@pytest.mark.asyncio
async def test_adecode_token_rejects_expired(expired_jwt, valid_settings):
    with pytest.raises(AuthentikateTokenExpired):
        await adecode_token(expired_jwt, valid_settings)


def make_token(**overrides) -> JWTToken:
    defaults = dict(
        sub="1",
        iss="test_issuer",
        exp=datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=1),
        iat=datetime.datetime.now(datetime.timezone.utc),
        preferred_username="tester",
        client_id="client",
        scope="read",
        roles=["special"],
        raw="raw",
        active_org="org",
    )
    defaults.update(overrides)
    return JWTToken(**defaults)


def test_changed_hash_is_stable_and_sensitive():
    token = make_token()
    same = make_token()
    assert token.changed_hash == same.changed_hash
    assert len(token.changed_hash) == 64  # sha256 hexdigest

    assert token.changed_hash != make_token(roles=["other"]).changed_hash
    assert token.changed_hash != make_token(active_org="other").changed_hash


def test_jwt_timestamps_are_utc_aware():
    token = JWTToken(
        sub="1",
        iss="test_issuer",
        exp=1735689600,
        iat=1735686000,
        preferred_username="tester",
        client_id="client",
        scope="read",
        roles=[],
        raw="raw",
    )
    assert token.exp.tzinfo == datetime.timezone.utc
    assert token.iat.tzinfo == datetime.timezone.utc


class FakeRequest:
    def __init__(self, token: JWTToken) -> None:
        self.user = object()
        self._extensions = {"token": token}

    def get_extension(self, name: str):
        return self._extensions[name]


def make_info(token: JWTToken) -> SimpleNamespace:
    return SimpleNamespace(
        context=SimpleNamespace(request=FakeRequest(token))
    )


def test_any_scope_of_checks_scopes_not_roles():
    # The token has "special" as a role but not as a scope, so a scope
    # requirement of "special" must fail.
    token = make_token(scope="read", roles=["special"])
    ext = AuthExtension(any_scope_of=["special"])

    with pytest.raises(GraphQLError, match="scopes"):
        ext.resolve(lambda source, info: "ok", None, make_info(token))

    ext = AuthExtension(any_scope_of=["read"])
    assert ext.resolve(lambda source, info: "ok", None, make_info(token)) == "ok"


@pytest.mark.asyncio
async def test_resolve_async_enforces_any_scope_and_any_role():
    token = make_token(scope="read", roles=["special"])

    async def next_(source, info):
        return "ok"

    with pytest.raises(GraphQLError, match="scopes"):
        await AuthExtension(any_scope_of=["special"]).resolve_async(
            next_, None, make_info(token)
        )

    with pytest.raises(GraphQLError, match="roles"):
        await AuthExtension(any_role_of=["missing"]).resolve_async(
            next_, None, make_info(token)
        )

    assert (
        await AuthExtension(
            any_scope_of=["read"], any_role_of=["special"]
        ).resolve_async(next_, None, make_info(token))
        == "ok"
    )


def test_sync_expand_user_links_organization_by_slug(db, valid_jwt, valid_settings):
    token = decode_token(valid_jwt, valid_settings)

    user = expand_user_from_token(token)

    assert user.active_organization is not None
    assert user.active_organization.slug == token.active_org
    assert Organization.objects.filter(slug=token.active_org).count() == 1


@pytest.mark.asyncio
async def test_token_roles_do_not_become_django_groups(db, valid_jwt, valid_settings):
    """Token roles must never be mirrored into Django's permission system.

    Mirroring them meant any IdP role name that happened to match a locally
    managed, permission-bearing Group silently granted those permissions.
    Roles now live on the token and on Membership, and are enforced in the
    Strawberry layer instead.
    """
    token = decode_token(valid_jwt, valid_settings)

    user = await aexpand_user_from_token(token)

    group_names = [name async for name in user.groups.values_list("name", flat=True)]
    assert group_names == []
    assert await Group.objects.acount() == 0


@pytest.fixture(scope="session")
def malformed_claims_jwt(valid_claims, key_pair_str):
    key = RSAKey.import_key(key_pair_str.private_key)
    claims = {k: v for k, v in valid_claims.items() if k != "client_id"}
    return jwt.encode({"alg": "RS256", "kid": "1"}, claims, key)


def test_decode_token_rejects_malformed_claims(malformed_claims_jwt, valid_settings):
    with pytest.raises(MalformedJwtTokenError):
        decode_token(malformed_claims_jwt, valid_settings)


@pytest.mark.asyncio
async def test_adecode_token_rejects_malformed_claims(
    malformed_claims_jwt, valid_settings
):
    with pytest.raises(MalformedJwtTokenError):
        await adecode_token(malformed_claims_jwt, valid_settings)


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_preferred_username_resolves_from_first_name():
    @strawberry.type
    class Query:
        @strawberry.field
        def me(self) -> UserType:
            return User(username="x", first_name="hello", sub="1")

    schema = strawberry.Schema(query=Query)
    result = schema.execute_sync("{ me { sub preferredUsername } }")

    assert result.errors is None
    assert result.data == {"me": {"sub": "1", "preferredUsername": "hello"}}


@pytest.mark.asyncio
async def test_roles_are_tracked_on_the_membership(db, valid_jwt, valid_settings):
    """Role changes are reflected on the org-scoped Membership, not on Groups."""
    token = decode_token(valid_jwt, valid_settings)
    first = token.model_copy(update={"roles": ["a", "b"]})
    second = token.model_copy(update={"roles": ["b", "c"]})

    context = await aexpand_token_context(first)
    assert sorted(context.membership.roles) == ["a", "b"]

    context = await aexpand_token_context(second)
    assert sorted(context.membership.roles) == ["b", "c"]
    assert await Group.objects.acount() == 0
