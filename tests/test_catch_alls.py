"""The service's catch-all scope and admin role pass every scope and role check; a guest never
passes on a role this way; ``enforce_scopes`` off lets missing scopes through."""

import copy
from typing import Any

import pytest
from django.conf import settings
from kante.testing import GraphQLHttpTestClient
from test_project.asgi import application

from authentikate.catch_alls import declare_catch_alls


@pytest.fixture
def service(transactional_db):
    """The test project with `everything` / `boss` as its catch-alls, and the static tokens below."""
    original = settings.AUTHENTIKATE
    settings.AUTHENTIKATE = copy.deepcopy(original)
    settings.AUTHENTIKATE["AUDIENCE"] = "12"
    settings.AUTHENTIKATE["SCOPED_TOKENS"] = "self"
    settings.AUTHENTIKATE["STATIC_TOKENS"] = {
        "reader": {"sub": "reader", "iss": "lok", "scope": "openid read"},
        "all": {"sub": "all", "iss": "lok", "scope": "openid everything"},
        "boss": {"sub": "boss", "iss": "lok", "roles": ["boss"], "scope": "openid"},
        "member": {"sub": "member", "iss": "lok", "roles": ["editor"], "scope": "openid"},
        "guest": {"sub": "guest", "iss": "lok", "roles": ["boss"], "collabs": {"12": {"5": ["boss"]}}, "scope": "openid"},
    }
    declare_catch_alls(scope="everything", role="boss")
    yield
    declare_catch_alls(scope=None, role=None)
    settings.AUTHENTIKATE = original


async def _run(token: str, query: str) -> dict[str, Any]:
    client = GraphQLHttpTestClient(application=application, headers={"Authorization": f"Bearer {token}"})
    return await client.execute(query=query)


def _reason(answer: dict[str, Any]) -> str | None:
    errors = answer.get("errors") or []
    return errors[0]["extensions"].get("reason") if errors else None


@pytest.mark.asyncio
async def test_a_specific_scope_is_not_another(service) -> None:
    answer = await _run("reader", "mutation { requireWrite }")
    assert _reason(answer) == "INSUFFICIENT_SCOPE"


@pytest.mark.asyncio
async def test_the_all_scope_passes_any_scope(service) -> None:
    write = await _run("all", "mutation { requireWrite }")
    read = await _run("all", "mutation { requireRead }")
    assert write["data"]["requireWrite"] is not None, write
    assert read["data"]["requireRead"] is not None, read


@pytest.mark.asyncio
async def test_the_admin_role_passes_any_role(service) -> None:
    answer = await _run("boss", "mutation { administrate }")
    assert answer["data"]["administrate"] == "done", answer


@pytest.mark.asyncio
async def test_another_role_does_not(service) -> None:
    answer = await _run("member", "mutation { administrate }")
    assert _reason(answer) == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_a_guest_does_not_pass_on_the_admin_role(service) -> None:
    refused = await _run("guest", "mutation { administrate }")
    assert _reason(refused) == "FULL_MEMBERSHIP_REQUIRED"
    # Even where guests may write, a collaboration granting the admin role is not one granting `editor`.
    opted_in = await _run("guest", "mutation { annotate }")
    assert _reason(opted_in) == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_without_enforcement_a_missing_scope_passes(service) -> None:
    settings.AUTHENTIKATE["ENFORCE_SCOPES"] = False
    answer = await _run("reader", "mutation { requireWrite }")
    assert answer["data"]["requireWrite"] is not None, answer
