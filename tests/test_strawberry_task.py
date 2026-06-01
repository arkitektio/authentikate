import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from kante.context import HttpContext, UniversalRequest

from authentikate.base_models import JWTToken
from authentikate.strawberry.extension import AuthentikateExtension


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
        response=SimpleNamespace(),
        headers={
            "Authorization": "Bearer any-token",
            "Rekuest-Task": f"id=task-1,parent=,args={encoded_args},user=1,app=app-1,action=run",
        },
    )

    extension = AuthentikateExtension()
    extension.execution_context = SimpleNamespace(context=context)
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
        response=SimpleNamespace(),
        headers={
            "Authorization": "Bearer any-token",
        },
    )

    extension = AuthentikateExtension()
    extension.execution_context = SimpleNamespace(context=context)
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
        response=SimpleNamespace(),
        headers={
            "Authorization": "Bearer any-token",
            "Rekuest-Task": "id=task-1,parent=,args=%7B%22x%22%3A1%7D,user=1,app=app-1,action=run",
        },
    )

    extension = AuthentikateExtension()
    extension.execution_context = SimpleNamespace(context=context)
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
