"""Tests for the machine-readable codes attached to auth failures.

A client needs to tell an expired token (refresh and retry) from a missing scope
(never going to work) without parsing English. Every failure carries
``extensions.code`` -- kante's coarse category -- plus ``extensions.reason`` for
the specific one.
"""

import datetime
import inspect
from types import SimpleNamespace
from typing import Any

import pytest
from graphql import GraphQLError
from kante.errors import KanteError

from authentikate import errors
from authentikate.base_models import AuthentikateSettings, JWTToken, StaticToken
from authentikate.strawberry.directives import AuthExtension
from authentikate.strawberry.errors import AuthentikateGraphQLError, to_graphql_error

VALID_CODES = {"UNAUTHENTICATED", "PERMISSION_DENIED", "INTERNAL_ERROR"}


def _error_classes() -> list[type]:
    """Every exception class authentikate defines."""
    return [
        obj
        for _, obj in inspect.getmembers(errors, inspect.isclass)
        if issubclass(obj, BaseException) and obj.__module__ == errors.__name__
    ]


# --- the vocabulary itself ---------------------------------------------------


@pytest.mark.parametrize("cls", _error_classes(), ids=lambda c: c.__name__)
def test_every_error_declares_a_code_reason_and_client_message(cls: type) -> None:
    """A newly added error must not ship uncoded.

    This is the guard: adding an exception without these attributes fails here
    rather than silently reaching clients as an untyped error.
    """
    assert getattr(cls, "code", None) in VALID_CODES, cls.__name__
    assert isinstance(getattr(cls, "reason", None), str) and cls.reason, cls.__name__
    assert isinstance(getattr(cls, "client_message", None), str), cls.__name__
    assert cls.client_message.strip(), cls.__name__


def test_client_messages_do_not_end_up_empty_or_templated() -> None:
    """`client_message` is a fixed sentence, never a format string."""
    for cls in _error_classes():
        assert "{" not in cls.client_message, cls.__name__


def test_infrastructure_failures_are_not_reported_as_denials() -> None:
    """A JWKS fetch failure is a server fault, not a verdict on the credentials.

    Coding it as a denial would tell the client to re-authenticate against a
    problem no credential can fix.
    """
    assert errors.JwksError.code == "INTERNAL_ERROR"
    assert errors.ProvenanceNotConfiguredError.code == "INTERNAL_ERROR"


def test_credential_failures_are_unauthenticated() -> None:
    """These are the ones that should make a client refresh or re-login."""
    for cls in (
        errors.AuthentikateTokenExpired,
        errors.MalformedJwtTokenError,
        errors.InvalidJwtTokenError,
        errors.NoAuthorizationHeader,
        errors.MalformedAuthorizationHeader,
        errors.KeyNotFoundError,
    ):
        assert cls.code == "UNAUTHENTICATED", cls.__name__


def test_token_expired_is_distinguishable() -> None:
    """The single most useful reason: it is what tells a client to refresh."""
    assert errors.AuthentikateTokenExpired.reason == "TOKEN_EXPIRED"
    assert errors.AuthentikateTokenExpired.reason != errors.InvalidJwtTokenError.reason


# --- translation to a GraphQL error ------------------------------------------


def test_to_graphql_error_carries_code_and_reason() -> None:
    err = to_graphql_error(errors.AuthentikateTokenExpired("token exp 12345 expired"))

    assert isinstance(err, KanteError)
    assert isinstance(err, GraphQLError)  # so existing handlers still catch it
    assert err.extensions["code"] == "UNAUTHENTICATED"
    assert err.extensions["reason"] == "TOKEN_EXPIRED"


def test_authentication_errors_do_not_reflect_input_back(caplog: Any) -> None:
    """The rejected value is attacker-supplied; it belongs in the log, not the wire.

    Otherwise the error surface becomes a probe for what this service trusts.
    """
    secret_ish = "https://evil.example/realms/probe"
    exc = errors.InvalidJwtTokenError(f"Untrusted issuer: {secret_ish!r}")

    with caplog.at_level("WARNING", logger="authentikate.strawberry.errors"):
        err = to_graphql_error(exc)

    assert secret_ish not in str(err.message)
    assert err.extensions["reason"] == "TOKEN_INVALID"
    # ...but an operator can still see exactly what was rejected.
    assert secret_ish in caplog.text


# --- the field directives ----------------------------------------------------


class _FakeRequest:
    def __init__(self, token: JWTToken | None, roles: list[str] | None = None) -> None:
        self._token = token
        self._roles = roles

    @property
    def user(self) -> Any:
        if self._token is None:
            raise ValueError("User is not set in the request.")
        return SimpleNamespace(id=1)

    @property
    def membership(self) -> Any:
        if self._roles is None:
            raise ValueError("Membership is not set in the request.")
        return SimpleNamespace(roles=self._roles)

    def get_extension(self, name: str) -> Any:
        if self._token is None or name != "token":
            raise ValueError(f"Extension {name} is not set in the request.")
        return self._token


def _token(scope: str = "read", roles: list[str] | None = None) -> JWTToken:
    now = datetime.datetime.now(datetime.timezone.utc)
    return JWTToken.model_validate(
        {
            "sub": "1",
            "iss": "test-issuer",
            "exp": int((now + datetime.timedelta(hours=1)).timestamp()),
            "iat": int(now.timestamp()),
            "client_id": "c",
            "preferred_username": "u",
            "roles": roles if roles is not None else ["reader"],
            "scope": scope,
            "raw": "raw",
        }
    )


def _info(token: JWTToken | None, org_roles: list[str] | None = None) -> Any:
    return SimpleNamespace(
        context=SimpleNamespace(request=_FakeRequest(token, org_roles))
    )


def _raises(extension: AuthExtension, info: Any) -> AuthentikateGraphQLError:
    with pytest.raises(AuthentikateGraphQLError) as exc_info:
        extension.resolve(lambda source, info: "ok", None, info)
    return exc_info.value


def test_unauthenticated_field_access() -> None:
    err = _raises(AuthExtension(scopes=["read"]), _info(None))

    assert err.extensions["code"] == "UNAUTHENTICATED"
    assert err.extensions["reason"] == "NOT_AUTHENTICATED"


@pytest.mark.parametrize(
    "extension,reason,detail_key,detail",
    [
        (AuthExtension(scopes=["admin"]), "INSUFFICIENT_SCOPE", "requiredScopes", ["admin"]),
        (
            AuthExtension(any_scope_of=["a", "b"]),
            "INSUFFICIENT_SCOPE",
            "requiredAnyScopeOf",
            ["a", "b"],
        ),
        (AuthExtension(roles=["admin"]), "INSUFFICIENT_ROLE", "requiredRoles", ["admin"]),
        (
            AuthExtension(any_role_of=["x", "y"]),
            "INSUFFICIENT_ROLE",
            "requiredAnyRoleOf",
            ["x", "y"],
        ),
    ],
)
def test_authorization_failures_name_the_requirement(
    extension: AuthExtension, reason: str, detail_key: str, detail: list[str]
) -> None:
    """Echoing the requirement is safe: the schema directive already publishes it."""
    err = _raises(extension, _info(_token()))

    assert err.extensions["code"] == "PERMISSION_DENIED"
    assert err.extensions["reason"] == reason
    assert err.extensions[detail_key] == detail


def test_org_role_failure_is_distinguishable_from_a_global_role_failure() -> None:
    """A client should be able to tell "wrong org" from "wrong account"."""
    err = _raises(AuthExtension(org_roles=["owner"]), _info(_token(), ["member"]))

    assert err.extensions["reason"] == "INSUFFICIENT_ORGANIZATION_ROLE"
    assert err.extensions["requiredOrganizationRoles"] == ["owner"]

    err = _raises(
        AuthExtension(any_org_role_of=["owner", "admin"]), _info(_token(), ["member"])
    )
    assert err.extensions["requiredAnyOrganizationRoleOf"] == ["owner", "admin"]


# --- end to end, through the real authentication path ------------------------


@pytest.mark.asyncio
async def test_expired_token_reports_token_expired_end_to_end() -> None:
    """What a client actually receives for the most common recoverable failure."""
    from authentikate.utils import authenticate_token

    past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    settings = AuthentikateSettings(
        issuers=[], static_tokens={"tok": StaticToken(sub="u", exp=past)}
    )

    with pytest.raises(errors.AuthentikateTokenExpired) as exc_info:
        await authenticate_token("tok", settings)

    err = to_graphql_error(exc_info.value)
    assert err.extensions == {"code": "UNAUTHENTICATED", "reason": "TOKEN_EXPIRED"}


@pytest.mark.asyncio
async def test_missing_authorization_header_reports_its_own_reason() -> None:
    from authentikate.utils import authenticate_header

    settings = AuthentikateSettings(issuers=[])

    with pytest.raises(errors.NoAuthorizationHeader) as exc_info:
        await authenticate_header({"Content-Type": "application/json"}, settings)

    err = to_graphql_error(exc_info.value)
    assert err.extensions["reason"] == "NO_AUTHORIZATION_HEADER"


# --- on the wire -------------------------------------------------------------


async def _execute(headers: dict[str, str], query: str = "query { me { sub } }") -> Any:
    from kante.testing import GraphQLHttpTestClient

    from test_project.asgi import application

    client = GraphQLHttpTestClient(application=application, headers=headers)
    return await client.execute(query=query)


@pytest.mark.asyncio
async def test_codes_reach_the_response_body(db: Any) -> None:
    """The whole point: a client can branch on this without parsing English."""
    answer = await _execute({"Authorization": "Bearer not-a-jwt"})

    assert answer["data"] is None
    extensions = answer["errors"][0]["extensions"]
    assert extensions["code"] == "UNAUTHENTICATED"
    assert extensions["reason"] == "TOKEN_MALFORMED"


@pytest.mark.asyncio
async def test_missing_header_reaches_the_wire_with_its_own_reason(db: Any) -> None:
    answer = await _execute({})

    extensions = answer["errors"][0]["extensions"]
    assert extensions["code"] == "UNAUTHENTICATED"
    assert extensions["reason"] == "NO_AUTHORIZATION_HEADER"


@pytest.mark.asyncio
async def test_wire_message_does_not_echo_the_rejected_token(db: Any) -> None:
    """A bad credential must not be reflected back in the response."""
    answer = await _execute({"Authorization": "Bearer probe-value-12345"})

    assert "probe-value-12345" not in answer["errors"][0]["message"]
