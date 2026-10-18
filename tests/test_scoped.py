"""Scoped members: a token with an ``objects`` claim, shared a few objects only."""

import asyncio
import copy
from typing import Any

import pytest
from django.conf import settings
from kante.testing import GraphQLHttpTestClient, GraphQLWebSocketTestClient

from authentikate import scoped
from authentikate.base_models import AuthentikateSettings, JWTToken, StaticToken
from authentikate.errors import FullMembershipRequired, ScopedTokenUnsupported
from authentikate.grants import ObjectGrant, parse_grant
from authentikate.utils import authenticate_token
from test_project.asgi import application

GRANTS = {"3": ["@mikro/arraydataset:42#derived", "@mikro/scene:7", "not a grant"], "9": ["@mikro/scene:1"]}


@pytest.fixture(autouse=True)
def _no_enforcer():
    """Every test starts in a process that narrows nothing."""
    scoped.stop_enforcing()
    yield
    scoped.stop_enforcing()


def _token(**claims: Any) -> StaticToken:
    return StaticToken(sub="guest", roles=[], **claims)


def _settings(**options: Any) -> AuthentikateSettings:
    return AuthentikateSettings(
        audience="*",
        issuers=[],
        static_tokens={"scoped": _token(objects=GRANTS), "full": StaticToken(sub="member")},
        **options,
    )


# --- the claim --------------------------------------------------------------------------


def test_a_token_without_objects_is_a_full_member() -> None:
    assert not StaticToken(sub="member").is_scoped
    assert StaticToken(sub="member").grants_for("3") == ()


def test_empty_objects_share_nothing() -> None:
    token = _token(objects={})
    assert token.is_scoped
    assert token.grants_for("3") == ()


def test_grants_are_read_for_one_hub_and_unreadable_ones_dropped() -> None:
    token = _token(objects=GRANTS)
    assert token.grants_for("3") == (
        ObjectGrant("@mikro/arraydataset", "42", "derived"),
        ObjectGrant("@mikro/scene", "7"),
    )
    assert token.grants_for("9") == (ObjectGrant("@mikro/scene", "1"),)
    assert token.grants_for("4") == ()


@pytest.mark.parametrize("claim", [["@mikro/scene:7"], {"3": "@mikro/scene:7"}, {"3": [7]}])
def test_an_objects_claim_of_another_shape_is_refused(claim: Any) -> None:
    with pytest.raises(ValueError):
        JWTToken(**{**StaticToken(sub="x").model_dump(), "objects": claim})


@pytest.mark.parametrize(
    "raw",
    [
        "@mikro/arraydataset:42",
        "@mikro/arraydataset:42#derived",
        "@kraph.v2/node-x:a_b.c-1#self-and-more",
        "@mikro/image:42~8",
        "@mikro/image:42#derived~8",
        "@mikro/image:42~user.name-1",
    ],
)
def test_parse_grant_round_trips_lok_format(raw: str) -> None:
    assert str(parse_grant(raw)) == raw.removesuffix("#self")


@pytest.mark.parametrize(
    "raw",
    [
        "@Mikro/arraydataset:42",
        "mikro/arraydataset:42",
        "@mikro/arraydataset",
        "@mikro/arraydataset:",
        "@mikro/x:1#",
        "@mikro/x:1#Derived",
        "@mikro/x:a:b",
        "@mikro/x:1~",
        "@mikro/x:~8",
        "@mikro/x:1~8~9",
        "@mikro/x:1#~8",
        "@mikro/x:1~8#derived",
        "@mikro/x:1~a/b",
    ],
)
def test_parse_grant_refuses_what_lok_would_not_write(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_grant(raw)


def test_a_grant_names_its_sharer() -> None:
    assert parse_grant("@mikro/image:42#derived~8") == ObjectGrant("@mikro/image", "42", "derived", "8")
    assert parse_grant("@mikro/image:42").sharer is None


def test_sharers_and_dropping_theirs() -> None:
    token = _token(objects={"3": ["@mikro/image:1~8", "@mikro/image:2#derived~9", "@mikro/image:3"], "4": ["@mikro/scene:5~8"]})
    assert token.sharers == {"8", "9"}
    narrowed = token.without_sharers({"8"})
    assert narrowed.grants_for("3") == (ObjectGrant("@mikro/image", "2", "derived", "9"), ObjectGrant("@mikro/image", "3"))
    assert narrowed.grants_for("4") == ()
    assert narrowed.is_scoped and token.grants_for("4")  # the original is left as it was
    assert token.without_sharers(set()) is token
    assert StaticToken(sub="member").without_sharers({"8"}).objects is None


# --- accepting a scoped token -----------------------------------------------------------


def test_scoped_token_is_rejected_where_nothing_narrows() -> None:
    with pytest.raises(ScopedTokenUnsupported):
        asyncio.run(authenticate_token("scoped", _settings()))
    assert asyncio.run(authenticate_token("full", _settings())).sub == "member"


def test_scoped_token_is_accepted_where_narrowed_with_a_hub() -> None:
    scoped.enforce_scoped()
    assert asyncio.run(authenticate_token("scoped", _settings(hub=3))).is_scoped


def test_the_hub_may_come_from_the_enforcer() -> None:
    scoped.enforce_scoped(hub_resolver=lambda: "3")
    settings = _settings()
    assert asyncio.run(authenticate_token("scoped", settings)).is_scoped
    assert scoped.current_hub(settings) == "3"
    assert scoped.current_hub(_settings(hub="5")) == "5"


def test_narrowed_without_a_hub_is_rejected() -> None:
    scoped.enforce_scoped()
    with pytest.raises(ScopedTokenUnsupported):
        asyncio.run(authenticate_token("scoped", _settings()))
    assert asyncio.run(authenticate_token("full", _settings())).sub == "member"


def test_reject_rejects_even_where_narrowed() -> None:
    scoped.enforce_scoped()
    with pytest.raises(ScopedTokenUnsupported):
        asyncio.run(authenticate_token("scoped", _settings(hub="3", scoped_tokens="reject")))


def test_self_accepts_without_an_enforcer_or_hub() -> None:
    assert scoped.scoped_mode(_settings(scoped_tokens="self")) == "self"
    assert asyncio.run(authenticate_token("scoped", _settings(scoped_tokens="self"))).is_scoped


def test_require_full_member() -> None:
    assert scoped.require_full_member(StaticToken(sub="member")).sub == "member"
    with pytest.raises(FullMembershipRequired):
        scoped.require_full_member(_token(objects={}))
    with pytest.raises(FullMembershipRequired):
        scoped.require_full_member()  # no token on the request


# --- the GraphQL write gate -------------------------------------------------------------


@pytest.fixture
def scoped_service(db):
    """The test project accepting the static tokens ``scoped`` and ``full``, narrowed on hub 3."""
    original = settings.AUTHENTIKATE
    settings.AUTHENTIKATE = copy.deepcopy(original)
    settings.AUTHENTIKATE["HUB"] = "3"
    settings.AUTHENTIKATE["STATIC_TOKENS"] = {
        "scoped": {"sub": "guest", "iss": "lok", "roles": [], "objects": GRANTS, "scope": "read write"},
        "full": {"sub": "member", "iss": "lok", "scope": "read write"},
        "editor": {"sub": "editor", "iss": "lok", "roles": ["editor"], "scope": "read write"},
        "no-scene": {"sub": "guest", "iss": "lok", "roles": [], "objects": {"3": ["@mikro/image:1~8"]}},
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


SHARED = {"3": ["@mikro/image:1~8", "@mikro/image:2#derived~9", "@mikro/image:3"]}


@pytest.fixture
def shared_by_two(scoped_service):
    """The static token `shared` lists grants of sharers 8 and 9, and one that names none."""
    settings.AUTHENTIKATE["STATIC_TOKENS"]["shared"] = {"sub": "guest", "iss": "lok", "roles": [], "objects": SHARED}


def _member(sub: str, org: str, *, blocked: bool) -> None:
    from authentikate.models import Membership, Organization, User

    # Rows written through the app outlive a test here, so this is idempotent.
    user, _ = User.objects.get_or_create(sub=sub, iss="lok", defaults={"username": f"u{sub}"})
    organization, _ = Organization.objects.get_or_create(slug=org)
    Membership.objects.filter(user=user).delete()
    Membership.objects.create(user=user, organization=organization, blocked=blocked)


@pytest.mark.asyncio
async def test_a_blocked_sharer_takes_their_grants_along(shared_by_two) -> None:
    from asgiref.sync import sync_to_async

    await sync_to_async(_member)("8", "static_org", blocked=True)
    await sync_to_async(_member)("9", "static_org", blocked=False)
    answer = await _run("shared", 'query { grants(hub: "3") }')
    assert answer["data"]["grants"] == ["@mikro/image:2#derived~9", "@mikro/image:3"]


@pytest.mark.asyncio
async def test_a_sharer_blocked_elsewhere_or_unknown_here_still_shares(shared_by_two) -> None:
    from asgiref.sync import sync_to_async

    await sync_to_async(_member)("8", "another_org", blocked=True)
    answer = await _run("shared", 'query { grants(hub: "3") }')
    assert answer["data"]["grants"] == SHARED["3"]


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



# --- a mutation shares can permit, and what the schema says --------------------------------


@pytest.mark.asyncio
async def test_a_share_of_a_listed_structure_opens_the_mutation(scoped_service) -> None:
    answer = await _run("scoped", "mutation { annotate }")
    assert answer["data"]["annotate"] == "annotated"  # the role is the sharer's to hold, checked by the resolver


@pytest.mark.asyncio
async def test_no_share_of_a_listed_structure_is_refused(scoped_service) -> None:
    answer = await _run("no-scene", "mutation { annotate }")
    assert _reason(answer) == "SCOPED_READ_ONLY"


@pytest.mark.asyncio
async def test_a_member_still_needs_the_role(scoped_service) -> None:
    assert _reason(await _run("full", "mutation { annotate }")) == "INSUFFICIENT_ROLE"
    assert (await _run("editor", "mutation { annotate }"))["data"]["annotate"] == "annotated"


def test_the_schema_says_who_may_and_through_which_share() -> None:
    from test_project.schema import schema

    sdl = str(schema)
    lines = {line.strip().split(":")[0]: line.strip() for line in sdl.splitlines() if line.startswith("  ")}
    assert lines["annotate"] == 'annotate: String! @auth(any_role_of: ["editor"], allow_scoped: true) @shared(by: ["@mikro/scene#annotate"])'
    assert lines["yieldOpen"] == "yieldOpen: String! @auth"  # only what a field requires is said
    assert "directive @shared(by: [String!]!) on OBJECT | FIELD_DEFINITION" in sdl



@pytest.mark.asyncio
async def test_a_resolvers_refusal_reaches_the_client_with_its_code(scoped_service) -> None:
    answer = await _run("scoped", "mutation { refuse }")
    (error,) = answer["errors"]
    assert error["extensions"]["code"] == "PERMISSION_DENIED"
    assert error["extensions"]["reason"] == "SHARE_INSUFFICIENT"
    assert error["message"] == "What was shared with you does not permit this."  # the detail stays in the log
