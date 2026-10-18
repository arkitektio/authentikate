"""Guests: a token with a ``collabs`` claim, granted a few collaborations of a service instance only."""

import asyncio
import copy
from typing import Any

import pytest
from django.conf import settings
from kante.testing import GraphQLHttpTestClient, GraphQLWebSocketTestClient

from authentikate import scoped
from authentikate.base_models import AuthentikateSettings, StaticToken
from authentikate.errors import FullMembershipRequired, ScopedTokenUnsupported
from authentikate.utils import authenticate_token
from test_project.asgi import application

COLLABS = {"12": {"5": ["editor"], "9": []}, "13": {"1": ["admin"]}}


@pytest.fixture(autouse=True)
def _no_enforcer():
    """Every test starts in a process that serves no guests."""
    scoped.stop_enforcing()
    yield
    scoped.stop_enforcing()


def _token(**claims: Any) -> StaticToken:
    return StaticToken(sub="guest", roles=[], **claims)


def _settings(**options: Any) -> AuthentikateSettings:
    return AuthentikateSettings(
        **{"audience": "*", **options},
        issuers=[],
        static_tokens={"scoped": _token(collabs=COLLABS), "full": StaticToken(sub="member")},
    )


# --- the claim --------------------------------------------------------------------------


def test_a_token_without_collabs_is_a_full_member() -> None:
    assert not StaticToken(sub="member").is_scoped
    assert StaticToken(sub="member").collabs_here("12") == {}


def test_empty_collabs_grant_nothing() -> None:
    token = _token(collabs={})
    assert token.is_scoped
    assert token.collabs_here("12") == {}


def test_collaborations_are_read_for_one_instance_with_their_roles() -> None:
    token = _token(collabs=COLLABS)
    assert token.collabs_here("12") == {"5": ("editor",), "9": ()}
    assert token.collabs_here("14") == {}
    assert token.collabs_here(None) == {}


@pytest.mark.parametrize("claim", [["5"], {"12": ["5"]}, {"12": {"5": "editor"}}, {"12": {"5": [1]}}])
def test_a_collabs_claim_of_another_shape_is_refused(claim: Any) -> None:
    with pytest.raises(ValueError):
        _token(collabs=claim)


# --- accepting a guest's token ----------------------------------------------------------


def test_a_guest_is_rejected_where_no_collaboration_holds_reads() -> None:
    with pytest.raises(ScopedTokenUnsupported):
        asyncio.run(authenticate_token("scoped", _settings()))
    assert asyncio.run(authenticate_token("full", _settings())).sub == "member"


def test_a_guest_is_accepted_where_held_and_the_audience_names_the_instance() -> None:
    scoped.enforce_scoped()
    assert asyncio.run(authenticate_token("scoped", _settings(audience="12"))).is_scoped
    assert scoped.current_instance(_settings(audience="12")) == "12"
    assert scoped.current_instance(_settings()) is None  # `*` names no instance


def test_held_without_an_instance_is_rejected() -> None:
    scoped.enforce_scoped()
    with pytest.raises(ScopedTokenUnsupported):
        asyncio.run(authenticate_token("scoped", _settings()))
    assert asyncio.run(authenticate_token("full", _settings())).sub == "member"


def test_reject_rejects_even_where_held() -> None:
    scoped.enforce_scoped()
    with pytest.raises(ScopedTokenUnsupported):
        asyncio.run(authenticate_token("scoped", _settings(audience="12", scoped_tokens="reject")))


def test_self_accepts_without_an_enforcer_or_instance() -> None:
    assert scoped.scoped_mode(_settings(scoped_tokens="self")) == "self"
    assert asyncio.run(authenticate_token("scoped", _settings(scoped_tokens="self"))).is_scoped


def test_require_full_member() -> None:
    assert scoped.require_full_member(StaticToken(sub="member")).sub == "member"
    with pytest.raises(FullMembershipRequired):
        scoped.require_full_member(_token(collabs={}))
    with pytest.raises(FullMembershipRequired):
        scoped.require_full_member()  # no token on the request


# --- the GraphQL write gate -------------------------------------------------------------


@pytest.fixture
def scoped_service(db):
    """The test project serving guests on instance 12, with the static tokens below."""
    original = settings.AUTHENTIKATE
    settings.AUTHENTIKATE = copy.deepcopy(original)
    settings.AUTHENTIKATE["AUDIENCE"] = "12"
    settings.AUTHENTIKATE["STATIC_TOKENS"] = {
        "scoped": {"sub": "guest", "iss": "lok", "roles": [], "collabs": COLLABS, "scope": "read write"},
        "viewer": {"sub": "guest", "iss": "lok", "roles": [], "collabs": {"12": {"9": []}, "13": {"1": ["editor"]}}, "scope": "read write"},
        "full": {"sub": "member", "iss": "lok", "scope": "read write"},
        "editor": {"sub": "editor", "iss": "lok", "roles": ["editor"], "scope": "read write"},
    }
    scoped.enforce_scoped()
    yield
    settings.AUTHENTIKATE = original


async def _run(token: str, query: str) -> dict[str, Any]:
    client = GraphQLHttpTestClient(application=application, headers={"Authorization": f"Bearer {token}"})
    return await client.execute(query=query)


def _reason(answer: dict[str, Any]) -> str | None:
    errors = answer.get("errors") or []
    return errors[0]["extensions"].get("reason") if errors else None


@pytest.mark.asyncio
async def test_a_guest_reads_their_collabs_here(scoped_service) -> None:
    answer = await _run("scoped", "query { collabs }")
    assert answer["data"]["collabs"] == ["5:editor", "9:"]


@pytest.mark.asyncio
async def test_a_scoped_member_may_query(scoped_service) -> None:
    answer = await _run("scoped", "query { me { sub } }")
    assert answer["data"]["me"]["sub"] == "guest"


@pytest.mark.asyncio
async def test_a_scoped_member_may_not_mutate(scoped_service) -> None:
    answer = await _run("scoped", "mutation { requireRead }")
    assert _reason(answer) == "SCOPED_READ_ONLY"
    assert answer.get("data") is None


@pytest.mark.asyncio
async def test_the_same_mutation_passes_for_a_full_member(scoped_service) -> None:
    answer = await _run("full", "mutation { requireRead }")
    assert answer["data"]["requireRead"] == "User"


@pytest.mark.asyncio
async def test_an_opted_in_mutation_passes(scoped_service) -> None:
    answer = await _run("scoped", "mutation { presign __typename }")
    assert answer["data"]["presign"] == "signed"


@pytest.mark.asyncio
async def test_opting_in_is_per_root_field_through_fragments(scoped_service) -> None:
    mixed = await _run("scoped", "mutation { presign requireRead }")
    assert _reason(mixed) == "SCOPED_READ_ONLY"
    spread = await _run("scoped", "mutation { ...M } fragment M on Mutation { presign ... on Mutation { requireRead } }")
    assert _reason(spread) == "SCOPED_READ_ONLY"


@pytest.mark.asyncio
async def test_a_named_operation_is_judged_by_itself(scoped_service) -> None:
    client = GraphQLHttpTestClient(application=application, headers={"Authorization": "Bearer scoped"})
    document = "mutation A { presign } mutation B { requireRead }"
    passed = await client.execute(query=document, operation_name="A")
    assert passed["data"]["presign"] == "signed"
    refused = await client.execute(query=document, operation_name="B")
    assert _reason(refused) == "SCOPED_READ_ONLY"


@pytest.mark.asyncio
async def test_a_role_field_requires_full_membership(scoped_service) -> None:
    settings.AUTHENTIKATE["SCOPED_TOKENS"] = "self"  # no write gate: the field's own check answers
    answer = await _run("scoped", "mutation { administrate }")
    assert _reason(answer) == "FULL_MEMBERSHIP_REQUIRED"


@pytest.mark.asyncio
async def test_under_self_the_service_decides(scoped_service) -> None:
    settings.AUTHENTIKATE["SCOPED_TOKENS"] = "self"
    answer = await _run("scoped", "mutation { requireRead }")
    assert answer["data"]["requireRead"] == "User"


async def _subscribe(token: str, query: str) -> list[dict[str, Any]]:
    """Every frame a subscription answers with, errors included (the test client drops those)."""
    import json

    client = GraphQLWebSocketTestClient(application=application, connection_params={"token": token})
    await client.connect()
    await client.communicator.send_input(
        {"type": "websocket.receive", "text": json.dumps({"id": "1", "type": "start", "payload": {"query": query}})}
    )
    frames: list[dict[str, Any]] = []
    while True:
        try:
            message = await asyncio.wait_for(client.communicator.receive_output(), timeout=2)
        except asyncio.TimeoutError:
            break
        if message["type"] != "websocket.send":
            continue
        frame = json.loads(message["text"])
        frames.append(frame)
        if frame.get("type") in ("complete", "error"):
            break
    await client.communicator.send_input({"type": "websocket.disconnect", "code": 1000})
    await client.communicator.wait(timeout=1)
    return frames


@pytest.mark.asyncio
async def test_a_scoped_member_may_not_subscribe(scoped_service) -> None:
    frames = await _subscribe("scoped", "subscription { yieldUser { sub } }")
    assert "SCOPED_READ_ONLY" in json_of(frames)
    assert '"guest"' not in json_of(frames)


@pytest.mark.asyncio
async def test_no_subscription_is_open_to_a_scoped_member(scoped_service, monkeypatch) -> None:
    # Even one whose every root field claims to opt in.
    monkeypatch.setattr("authentikate.strawberry.extension.allows_scoped", lambda context: True)
    frames = await _subscribe("scoped", "subscription { yieldOpen }")
    assert "SCOPED_READ_ONLY" in json_of(frames)
    assert '"event"' not in json_of(frames)


def test_a_subscription_field_cannot_opt_in() -> None:
    from authentikate.strawberry.directives import AuthSubscribeExtension

    class Field:
        is_subscription = True
        directives: list[Any] = []

    with pytest.raises(AssertionError, match="cannot be opened"):
        AuthSubscribeExtension(allow_scoped=True).apply(Field())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_a_full_member_may_subscribe(scoped_service) -> None:
    frames = await _subscribe("full", "subscription { yieldUser { sub } }")
    assert '"member"' in json_of(frames)


def json_of(frames: list[dict[str, Any]]) -> str:
    import json

    return json.dumps(frames)


@pytest.mark.asyncio
async def test_full_members_only_view(scoped_service) -> None:
    from django.http import HttpResponse
    from django.test import RequestFactory

    from authentikate.vars import get_token

    @scoped.full_members_only
    def upload(request: Any) -> HttpResponse:
        token = get_token()
        return HttpResponse(token.sub if token else "")

    factory = RequestFactory()
    response = await upload(factory.get("/", HTTP_AUTHORIZATION="Bearer full"))
    assert response.content == b"member"
    with pytest.raises(FullMembershipRequired):
        await upload(factory.get("/", HTTP_AUTHORIZATION="Bearer scoped"))



# --- roles that hold inside a collaboration -------------------------------------------------------


@pytest.mark.asyncio
async def test_a_role_a_collaboration_holds_opens_the_field(scoped_service) -> None:
    answer = await _run("scoped", "mutation { annotate }")
    assert answer["data"]["annotate"] == "annotated"  # editor in collaboration 5; the resolver checks the target's collaboration


@pytest.mark.asyncio
async def test_a_role_held_only_in_another_instances_collaboration_does_not(scoped_service) -> None:
    answer = await _run("viewer", "mutation { annotate }")
    assert _reason(answer) == "INSUFFICIENT_ROLE"


@pytest.mark.asyncio
async def test_a_member_still_needs_the_role(scoped_service) -> None:
    assert _reason(await _run("full", "mutation { annotate }")) == "INSUFFICIENT_ROLE"
    assert (await _run("editor", "mutation { annotate }"))["data"]["annotate"] == "annotated"


def test_the_schema_says_who_may() -> None:
    from test_project.schema import schema

    sdl = str(schema)
    lines = {line.strip().split(":")[0]: line.strip() for line in sdl.splitlines() if line.startswith("  ")}
    assert lines["annotate"] == 'annotate: String! @auth(any_role_of: ["editor"], allow_scoped: true)'
    assert lines["yieldOpen"] == "yieldOpen: String! @auth"  # only what a field requires is said
    assert "@shared" not in sdl


@pytest.mark.asyncio
async def test_a_resolvers_refusal_reaches_the_client_with_its_code(scoped_service) -> None:
    answer = await _run("scoped", "mutation { refuse }")
    (error,) = answer["errors"]
    assert error["extensions"]["code"] == "PERMISSION_DENIED"
    assert error["extensions"]["reason"] == "SHARE_INSUFFICIENT"
    assert error["message"] == "What was shared with you does not permit this."  # the detail stays in the log
