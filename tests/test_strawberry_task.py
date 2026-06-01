import base64
from typing import Any, cast
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from kante.context import HttpContext, UniversalRequest

from authentikate.base_models import JWTToken
from authentikate.strawberry.extension import AuthentikateExtension
from authentikate.vars import get_client, get_organization, get_token, get_user


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


@pytest.mark.asyncio
async def test_http_context_sets_task_when_rekuest_header_present(token: JWTToken) -> None:
    encoded_args = base64.urlsafe_b64encode(b'{"x":1}').decode("utf-8").rstrip("=")
    request = UniversalRequest(_extensions={})
    context = HttpContext(
        request=request,
        response=cast(Any, SimpleNamespace()),
        headers={
            "Authorization": "Bearer any-token",
            "Rekuest-Task": f"id=task-1,parent=,args={encoded_args},user=1,app=app-1,action=run",
        },
    )

    extension = AuthentikateExtension()
    extension.execution_context = cast(Any, SimpleNamespace(context=context))
    extension.aexpand_token_context = AsyncMock(
        return_value=(
            SimpleNamespace(id=1, sub="1"),
            SimpleNamespace(id=1, client_id="client-1"),
            SimpleNamespace(id=1, slug="org-1"),
            SimpleNamespace(id=1),
        )
    )

    with patch(
        "authentikate.strawberry.extension.authenticate_header",
        new=AsyncMock(return_value=token),
    ):
        operation = extension.on_operation()
        await operation.__anext__()
        with pytest.raises(StopAsyncIteration):
            await operation.__anext__()

    assert request._task is not None
    assert request._task.id == "task-1"
    assert request._task.args == {"x": 1}
    assert request.get_extension("task").id == "task-1"


@pytest.mark.asyncio
async def test_http_context_keeps_task_empty_without_rekuest_header(token: JWTToken) -> None:
    request = UniversalRequest(_extensions={})
    context = HttpContext(
        request=request,
        response=cast(Any, SimpleNamespace()),
        headers={
            "Authorization": "Bearer any-token",
        },
    )

    extension = AuthentikateExtension()
    extension.execution_context = cast(Any, SimpleNamespace(context=context))
    extension.aexpand_token_context = AsyncMock(
        return_value=(
            SimpleNamespace(id=1, sub="1"),
            SimpleNamespace(id=1, client_id="client-1"),
            SimpleNamespace(id=1, slug="org-1"),
            SimpleNamespace(id=1),
        )
    )

    with patch(
        "authentikate.strawberry.extension.authenticate_header",
        new=AsyncMock(return_value=token),
    ):
        operation = extension.on_operation()
        await operation.__anext__()
        with pytest.raises(StopAsyncIteration):
            await operation.__anext__()

    assert request._task is None
    with pytest.raises(ValueError, match="Extension task is not set"):
        request.get_extension("task")


@pytest.mark.asyncio
async def test_http_context_keeps_task_empty_with_non_base64_args(token: JWTToken) -> None:
    request = UniversalRequest(_extensions={})
    context = HttpContext(
        request=request,
        response=cast(Any, SimpleNamespace()),
        headers={
            "Authorization": "Bearer any-token",
            "Rekuest-Task": "id=task-1,parent=,args=%7B%22x%22%3A1%7D,user=1,app=app-1,action=run",
        },
    )

    extension = AuthentikateExtension()
    extension.execution_context = cast(Any, SimpleNamespace(context=context))
    extension.aexpand_token_context = AsyncMock(
        return_value=(
            SimpleNamespace(id=1, sub="1"),
            SimpleNamespace(id=1, client_id="client-1"),
            SimpleNamespace(id=1, slug="org-1"),
            SimpleNamespace(id=1),
        )
    )

    with patch(
        "authentikate.strawberry.extension.authenticate_header",
        new=AsyncMock(return_value=token),
    ):
        operation = extension.on_operation()
        await operation.__anext__()
        with pytest.raises(StopAsyncIteration):
            await operation.__anext__()

    assert request._task is None
    with pytest.raises(ValueError, match="Extension task is not set"):
        request.get_extension("task")


@pytest.mark.asyncio
async def test_context_vars_reset_when_operation_raises(token: JWTToken) -> None:
    request = UniversalRequest(_extensions={})
    context = HttpContext(
        request=request,
        response=cast(Any, SimpleNamespace()),
        headers={
            "Authorization": "Bearer any-token",
        },
    )

    extension = AuthentikateExtension()
    extension.execution_context = cast(Any, SimpleNamespace(context=context))
    extension.aexpand_token_context = AsyncMock(
        return_value=(
            SimpleNamespace(id=1, sub="1"),
            SimpleNamespace(id=1, client_id="client-1"),
            SimpleNamespace(id=1, slug="org-1"),
            SimpleNamespace(id=1),
        )
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
