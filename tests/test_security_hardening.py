"""Regression tests for the remaining audit findings.

Covers the static-token guards, the organization allow-list, the JWKS refresh
throttle, and the blocked-membership checks that the sync and extension paths
used to skip.
"""

import asyncio
import datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from django.core.exceptions import ImproperlyConfigured
from graphql import GraphQLError
from joserfc.jwk import RSAKey

import authentikate.settings as authentikate_settings
from authentikate.base_models import AuthentikateSettings, JWTToken, StaticToken
from authentikate.errors import (
    AuthentikateTokenExpired,
    BlockedMembership,
    OrganizationNotAllowed,
)
from authentikate.expand import expand_user_from_token
from authentikate.models import Membership, Organization, User
from authentikate.settings import prepare_settings
from authentikate.strawberry.directives import AuthExtension
from authentikate.utils import authenticate_token

# --- static tokens -----------------------------------------------------------


def test_expired_static_token_is_rejected() -> None:
    """A static token's `exp` must be honoured, not merely decorative."""
    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    settings = AuthentikateSettings(
        issuers=[],
        static_tokens={"tok": StaticToken(sub="u", exp=past)},
    )

    with pytest.raises(AuthentikateTokenExpired):
        asyncio.run(authenticate_token("tok", settings))


def test_unexpired_static_token_is_accepted() -> None:
    settings = AuthentikateSettings(
        issuers=[],
        static_tokens={"tok": StaticToken(sub="u")},
    )

    assert asyncio.run(authenticate_token("tok", settings)).sub == "u"


def _reset_settings_cache() -> None:
    authentikate_settings.cached_settings = None


def test_static_tokens_are_refused_when_debug_is_off(settings: Any) -> None:
    """Static tokens skip signature verification, so they must not ship to prod."""
    settings.DEBUG = False
    settings.AUTHENTIKATE = {
        "ISSUERS": [],
        "STATIC_TOKENS": {"tok": {"sub": "u"}},
    }
    _reset_settings_cache()

    try:
        with pytest.raises(ImproperlyConfigured, match="STATIC_TOKENS"):
            prepare_settings()
    finally:
        _reset_settings_cache()


def test_static_tokens_allowed_with_explicit_escape_hatch(settings: Any) -> None:
    settings.DEBUG = False
    settings.AUTHENTIKATE = {
        "ISSUERS": [],
        "STATIC_TOKENS": {"tok": {"sub": "u"}},
        "ALLOW_STATIC_TOKENS_IN_PRODUCTION": True,
    }
    _reset_settings_cache()

    try:
        assert prepare_settings().static_tokens["tok"].sub == "u"
    finally:
        _reset_settings_cache()


# --- organization allow-list -------------------------------------------------


def _static_settings(**kwargs: Any) -> AuthentikateSettings:
    return AuthentikateSettings(
        issuers=[],
        static_tokens={"tok": StaticToken(sub="u", active_org="acme")},
        **kwargs,
    )


def test_organization_outside_the_allowlist_is_rejected() -> None:
    settings = _static_settings(allowed_organizations=["other"])

    with pytest.raises(OrganizationNotAllowed, match="acme"):
        asyncio.run(authenticate_token("tok", settings))


def test_organization_inside_the_allowlist_is_accepted() -> None:
    settings = _static_settings(allowed_organizations=["acme", "other"])

    assert asyncio.run(authenticate_token("tok", settings)).active_org == "acme"


def test_any_organization_is_accepted_when_allowlist_unset() -> None:
    """Default behaviour is unchanged, so existing deployments keep working."""
    assert asyncio.run(authenticate_token("tok", _static_settings())).active_org == "acme"


# --- JWKS refresh throttling -------------------------------------------------


def _jwks_session(jwk: dict[str, Any]) -> AsyncMock:
    session = AsyncMock()
    session.__aenter__.return_value = session
    session.__aexit__.return_value = False
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"keys": [jwk]}
    session.get.return_value = response
    return session


def test_unknown_kids_do_not_drive_unbounded_jwks_fetches(key_pair_str) -> None:
    """A stream of made-up `kid`s must not become a stream of issuer requests.

    The first refresh is always allowed so a rotated key is picked up promptly;
    subsequent ones inside the interval are served from cache.
    """
    jwk = RSAKey.import_key(key_pair_str.public_key).as_dict(kid="real")
    session = _jwks_session(jwk)

    with patch("authentikate.base_models.httpx.AsyncClient", return_value=session):
        settings = AuthentikateSettings(
            issuers=[
                {
                    "kind": "jwks_uri",
                    "iss": "http://issuer",
                    "jwks_uri": "http://issuer/jwks",
                }
            ]
        )
        issuer = settings.issuers[0]

        # Initial load.
        issuer.get_as_jwks()
        assert session.get.call_count == 1

        # First refresh after the load is allowed (key rotation must still work).
        issuer.refresh()
        assert session.get.call_count == 2

        # Everything after that is throttled.
        for _ in range(20):
            issuer.refresh()
        assert session.get.call_count == 2


# --- blocked memberships on every path ---------------------------------------


def _token(sub: str = "1", org: str = "org-1") -> JWTToken:
    return JWTToken.model_validate(
        {
            "sub": sub,
            "iss": "test-issuer",
            "exp": 2000000000,
            "iat": 1000000000,
            "client_id": "client-1",
            "preferred_username": "user-1",
            "roles": ["reader"],
            "scope": "read",
            "raw": "raw-token",
            "active_org": org,
        }
    )


def test_sync_expand_rejects_blocked_membership(db) -> None:
    """The sync path used to skip the membership check entirely."""
    # Distinct sub/org per test: async tests elsewhere are not rolled back
    # cleanly by pytest-django, so shared identifiers leak between files.
    token = _token(sub="sync-blocked", org="org-sync")

    # First call provisions the user, organization and membership.
    user = expand_user_from_token(token)

    organization = Organization.objects.get(slug="org-sync")
    Membership.objects.filter(user=user, organization=organization).update(blocked=True)

    with pytest.raises(BlockedMembership):
        expand_user_from_token(token)


@pytest.mark.asyncio
async def test_async_expand_rejects_blocked_membership(db) -> None:
    """The module-level async expander must match its sync twin."""
    from authentikate.expand import aexpand_user_from_token

    token = _token(sub="async-blocked", org="org-async")

    user = await aexpand_user_from_token(token)

    organization = await Organization.objects.aget(slug="org-async")
    await Membership.objects.filter(
        user=user, organization=organization
    ).aupdate(blocked=True)

    with pytest.raises(BlockedMembership):
        await aexpand_user_from_token(token)


@pytest.mark.asyncio
async def test_extension_user_expansion_rejects_blocked_membership(db) -> None:
    """`AuthentikateExtension.aexpand_user_from_token` skipped it too."""
    from authentikate.strawberry.extension import AuthentikateExtension

    token = _token(sub="ext-blocked", org="org-ext")
    extension = AuthentikateExtension()

    user = await extension.aexpand_user_from_token(token)

    organization = await Organization.objects.aget(slug="org-ext")
    await Membership.objects.filter(
        user=user, organization=organization
    ).aupdate(blocked=True)

    with pytest.raises(BlockedMembership):
        await extension.aexpand_user_from_token(token)


def test_token_roles_create_no_groups(db) -> None:
    """Belt and braces: expansion must not touch Django's permission system."""
    from django.contrib.auth.models import Group

    expand_user_from_token(_token(sub="no-groups", org="org-groups"))

    assert Group.objects.count() == 0
    assert User.objects.filter(sub="no-groups").exists()


# --- org-scoped role directives ----------------------------------------------


class _FakeRequest:
    """Minimal stand-in for kante's request object."""

    def __init__(self, token: JWTToken, roles: list[str] | None) -> None:
        self._token = token
        self._roles = roles

    @property
    def user(self) -> Any:
        return SimpleNamespace(id=1)

    @property
    def membership(self) -> Any:
        if self._roles is None:
            raise ValueError("Membership is not set in the request.")
        return SimpleNamespace(roles=self._roles)

    def get_extension(self, name: str) -> Any:
        if name != "token":
            raise ValueError(f"Extension {name} is not set in the request.")
        return self._token


def _info(roles: list[str] | None) -> Any:
    return SimpleNamespace(context=SimpleNamespace(request=_FakeRequest(_token(), roles)))


def _resolve(extension: AuthExtension, roles: list[str] | None) -> Any:
    return extension.resolve(lambda source, info: "ok", None, _info(roles))


def test_org_role_is_required_from_the_membership() -> None:
    assert _resolve(AuthExtension(org_roles=["admin"]), ["admin", "member"]) == "ok"

    with pytest.raises(GraphQLError, match="organization roles"):
        _resolve(AuthExtension(org_roles=["admin"]), ["member"])


def test_any_org_role_of() -> None:
    assert _resolve(AuthExtension(any_org_role_of=["admin", "owner"]), ["owner"]) == "ok"

    with pytest.raises(GraphQLError, match="organization roles"):
        _resolve(AuthExtension(any_org_role_of=["admin", "owner"]), ["member"])


def test_org_roles_fail_closed_without_a_membership() -> None:
    """No membership on the request means no org roles, not a bypass."""
    with pytest.raises(GraphQLError, match="organization roles"):
        _resolve(AuthExtension(org_roles=["admin"]), None)


def test_org_roles_are_independent_of_token_roles() -> None:
    """A global token role must not satisfy an org-scoped requirement.

    The token here carries `reader`; the membership does not.
    """
    with pytest.raises(GraphQLError, match="organization roles"):
        _resolve(AuthExtension(org_roles=["reader"]), ["member"])


# --- username derivation -----------------------------------------------------


def _username_token(iss: str, sub: str) -> JWTToken:
    return JWTToken.model_validate(
        {
            "sub": sub,
            "iss": iss,
            "exp": 2000000000,
            "iat": 1000000000,
            "client_id": "client-1",
            "preferred_username": "user-1",
            "roles": [],
            "scope": "read",
            "raw": "raw-token",
            "active_org": "org-1",
        }
    )


URL_ISSUER = "https://lok.my-org.com/realms/production"
LONG_ISSUER = "https://" + "very-long-subdomain." * 8 + "example.com/realms/x"


@pytest.mark.parametrize(
    "iss,sub",
    [
        (URL_ISSUER, "8f14e45f-ceea-467a-9c8e-6b1f3a2d5e77"),
        ("lok", "1"),
        (LONG_ISSUER, "u" * 80),
        ("https://idp.example", "user@example.com"),
    ],
)
def test_generated_username_is_valid_and_bounded(iss: str, sub: str) -> None:
    """The old `f"{iss}_{sub}"` failed Django's own username validator.

    URL issuers contain `:` and `/`, which UnicodeUsernameValidator rejects, and
    a long issuer plus a long sub can blow past max_length.
    """
    from authentikate.expand import USERNAME_MAX_LENGTH, token_to_username

    username = token_to_username(_username_token(iss, sub))

    assert len(username) <= USERNAME_MAX_LENGTH
    for validator in User._meta.get_field("username").validators:
        validator(username)  # raises ValidationError if invalid


def test_generated_username_is_stable() -> None:
    """The same token must always map to the same username."""
    from authentikate.expand import token_to_username

    token = _username_token(URL_ISSUER, "abc")
    assert token_to_username(token) == token_to_username(token)


def test_usernames_differ_when_sanitization_collides() -> None:
    """Sanitizing is lossy, so the digest is what keeps `username` unique.

    These two issuers differ only in characters that both get replaced. Without
    the digest suffix they would produce the same username and the second user
    to be provisioned would hit the unique constraint.
    """
    from authentikate.expand import token_to_username

    a = token_to_username(_username_token("https://a.example", "x"))
    b = token_to_username(_username_token("https-//a.example", "x"))

    assert a != b


def test_provisioned_user_passes_full_clean(db) -> None:
    """A user created from a URL-issuer token must be editable in the admin.

    `admin.py` registers User with a plain ModelAdmin, whose form runs
    `full_clean()`. With the old derivation that failed, so token-provisioned
    users could not be edited at all.
    """
    from authentikate.expand import expand_user_from_token

    token = _username_token(URL_ISSUER, "admin-editable")
    user = expand_user_from_token(token)

    user.full_clean(exclude=["password"])
