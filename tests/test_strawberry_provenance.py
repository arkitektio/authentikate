"""Tests for the AuthentikateExtension wiring the provenance token onto the request.

The provenance token arrives under the Rekuest task header (the legacy plaintext
task payload is gone). The extension decodes it — when provenance is configured —
and attaches it so resolvers can read ``info.context.request.provenance``.

These use a lightweight fake request rather than ``kante.context.UniversalRequest``
so the test does not depend on the kante release that renames ``set_task`` to
``set_provenance``; the fake mirrors the interface the extension relies on.
"""

import datetime
import uuid
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from joserfc import jwt
from joserfc.jwk import OKPKey
from kante.context import HttpContext

from authentikate import errors
from authentikate.base_models import AuthentikateSettings, JWTToken
from authentikate.provenance import CANONICALIZATION_VERSION
from authentikate.strawberry.extension import AuthentikateExtension
from authentikate.vars import get_client, get_organization, get_token, get_user

PROV_KID = "prov-1"


class _FakeRequest:
    """Records what the extension attaches; mirrors kante's UniversalRequest setters."""

    def __init__(self) -> None:
        self._extensions: dict[str, Any] = {}
        self._provenance: Any = None
        self._user: Any = None
        self._client: Any = None
        self._membership: Any = None
        self._organization: Any = None

    def set_user(self, user: Any) -> None:
        self._user = user

    def set_client(self, client: Any) -> None:
        self._client = client

    def set_membership(self, membership: Any) -> None:
        self._membership = membership

    def set_organization(self, organization: Any) -> None:
        self._organization = organization

    def set_provenance(self, provenance: Any) -> None:
        self._provenance = provenance

    def set_extension(self, name: str, value: Any) -> None:
        self._extensions[name] = value

    def get_extension(self, name: str) -> Any:
        if name not in self._extensions:
            raise ValueError(f"Extension {name} is not set in the request.")
        return self._extensions[name]


@pytest.fixture
def token() -> JWTToken:
    return JWTToken.model_validate(
        {
            "sub": "1",
            "iss": "test-issuer",
            "exp": 2000000000,
            "client_id": "client-1",
            "preferred_username": "user-1",
            "roles": ["reader"],
            "scope": "read",
            "iat": 1000000000,
            "raw": "raw-token",
        }
    )


@pytest.fixture
def ed_key() -> OKPKey:
    return OKPKey.generate_key("Ed25519")


@pytest.fixture
def settings(ed_key: OKPKey) -> AuthentikateSettings:
    pub = ed_key.as_dict(private=False, kid=PROV_KID)
    return AuthentikateSettings(
        issuers=[{"iss": "lok", "kind": "jwks_dict", "jwks": {"keys": [pub]}}],
        provenance={
            "issuers": [
                {"iss": "rekuest", "kind": "jwks_dict", "jwks": {"keys": [pub]}}
            ],
            "audience": "mikro",
        },
    )


@pytest.fixture
def bare_settings(ed_key: OKPKey) -> AuthentikateSettings:
    pub = ed_key.as_dict(private=False, kid=PROV_KID)
    return AuthentikateSettings(
        issuers=[{"iss": "lok", "kind": "jwks_dict", "jwks": {"keys": [pub]}}],
    )


def _provenance_token(ed_key: OKPKey) -> str:
    now = int(datetime.datetime.now().timestamp())
    claims = {
        "iss": "rekuest",
        "aud": ["mikro"],
        "sub": "user-42",
        "act": {"sub": "agent-7", "cid": "imagej-app"},
        "iat": now,
        "exp": now + 3600,
        "jti": uuid.uuid4().hex,
        "tsk": "9b1a",
        "ptk": None,
        "rtk": "9b1a",
        "rcb": "user-42",
        "ahs": "e3b0c44298fc1c14",
        "aha": CANONICALIZATION_VERSION,
    }
    return jwt.encode(
        {"alg": "EdDSA", "kid": PROV_KID}, claims, ed_key, algorithms=["EdDSA"]
    )


def _make_extension(
    settings: AuthentikateSettings, request: _FakeRequest, headers: dict[str, str]
) -> tuple[AuthentikateExtension, HttpContext]:
    context = HttpContext(
        request=cast(Any, request),
        response=cast(Any, SimpleNamespace()),
        headers=headers,
    )
    extension = AuthentikateExtension()
    extension.execution_context = cast(Any, SimpleNamespace(context=context))
    extension.get_settings = lambda: settings  # type: ignore[method-assign]
    extension.aexpand_token_context = AsyncMock(  # type: ignore[method-assign]
        return_value=(
            SimpleNamespace(id=1, sub="1"),
            SimpleNamespace(id=1, client_id="client-1"),
            SimpleNamespace(id=1, slug="org-1"),
            SimpleNamespace(id=1),
        )
    )
    return extension, context


async def _run(extension: AuthentikateExtension) -> None:
    operation = extension.on_operation()
    await operation.__anext__()
    with pytest.raises(StopAsyncIteration):
        await operation.__anext__()


@pytest.mark.asyncio
async def test_attaches_provenance_from_rekuest_task_header(
    token: JWTToken, ed_key: OKPKey, settings: AuthentikateSettings
) -> None:
    request = _FakeRequest()
    extension, _ = _make_extension(
        settings,
        request,
        {
            "Authorization": "Bearer any-token",
            "rekuest-task": _provenance_token(ed_key),
        },
    )

    with patch(
        "authentikate.strawberry.extension.authenticate_header",
        new=AsyncMock(return_value=token),
    ):
        await _run(extension)

    assert request._provenance is not None
    assert request._provenance.sub == "user-42"
    assert request._provenance.act.sub == "agent-7"
    assert request.get_extension("provenance").tsk == "9b1a"


@pytest.mark.asyncio
async def test_present_but_invalid_provenance_token_raises(
    token: JWTToken, settings: AuthentikateSettings
) -> None:
    request = _FakeRequest()
    extension, _ = _make_extension(
        settings,
        request,
        {
            "Authorization": "Bearer any-token",
            "rekuest-task": "this-is-not-a-valid-jwt",
        },
    )

    with patch(
        "authentikate.strawberry.extension.authenticate_header",
        new=AsyncMock(return_value=token),
    ):
        operation = extension.on_operation()
        # A provenance token IS present but cannot be validated, so the whole
        # operation fails closed instead of silently proceeding unprovenanced.
        with pytest.raises(errors.ProvenanceValidationError):
            await operation.__anext__()

    # No provenance was attached, and the context vars were reset on the way out.
    assert request._provenance is None
    assert get_token() is None


@pytest.mark.asyncio
async def test_no_provenance_header_leaves_request_unset(
    token: JWTToken, settings: AuthentikateSettings
) -> None:
    request = _FakeRequest()
    extension, _ = _make_extension(
        settings, request, {"Authorization": "Bearer any-token"}
    )

    with patch(
        "authentikate.strawberry.extension.authenticate_header",
        new=AsyncMock(return_value=token),
    ):
        await _run(extension)

    assert request._provenance is None
    with pytest.raises(ValueError, match="Extension provenance is not set"):
        request.get_extension("provenance")


@pytest.mark.asyncio
async def test_provenance_not_configured_skips_decode(
    token: JWTToken, ed_key: OKPKey, bare_settings: AuthentikateSettings
) -> None:
    request = _FakeRequest()
    extension, _ = _make_extension(
        bare_settings,
        request,
        {
            "Authorization": "Bearer any-token",
            "rekuest-task": _provenance_token(ed_key),
        },
    )

    with patch(
        "authentikate.strawberry.extension.authenticate_header",
        new=AsyncMock(return_value=token),
    ):
        await _run(extension)

    assert request._provenance is None


@pytest.mark.asyncio
async def test_context_vars_reset_when_operation_raises(
    token: JWTToken, settings: AuthentikateSettings
) -> None:
    request = _FakeRequest()
    extension, _ = _make_extension(
        settings, request, {"Authorization": "Bearer any-token"}
    )

    with patch(
        "authentikate.strawberry.extension.authenticate_header",
        new=AsyncMock(return_value=token),
    ):
        operation = cast(Any, extension.on_operation())
        await operation.__anext__()

        assert get_token() == token
        assert get_user() is not None
        assert get_client() is not None
        assert get_organization() is not None

        with pytest.raises(RuntimeError, match="boom"):
            await operation.athrow(RuntimeError("boom"))

    assert get_token() is None
    assert get_user() is None
    assert get_client() is None
    assert get_organization() is None
