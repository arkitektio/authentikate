"""An organization is its issuer's: ``"<iss>#<org>"``, so two issuers' org ``1`` never merge."""

import asyncio
import datetime

import pytest
from pydantic import ValidationError

from authentikate.base_models import AuthentikateSettings, JWTToken, StaticToken
from authentikate.errors import OrganizationNotAllowed
from authentikate.expand import aexpand_organization_from_token
from authentikate.models import Organization
from authentikate.provenance.models import ProvenanceToken
from authentikate.utils import authenticate_token


def make_token(**overrides) -> JWTToken:
    defaults = dict(
        sub="1",
        iss="https://lok.one",
        exp=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),
        iat=datetime.datetime.now(datetime.timezone.utc),
        preferred_username="tester",
        client_id="client",
        scope="read",
        roles=[],
        aud=["test-service"],
        raw="raw",
        org="1",
    )
    defaults.update(overrides)
    return JWTToken(**defaults)


def test_the_organization_is_named_with_its_issuer() -> None:
    assert make_token().org_identifier == "https://lok.one#1"
    assert make_token(org=None).org_identifier is None


def test_an_issuer_with_a_fragment_is_refused() -> None:
    with pytest.raises(ValidationError, match="must not contain '#'"):
        make_token(iss="https://lok.one#evil")


@pytest.mark.django_db
@pytest.mark.asyncio
async def test_two_issuers_with_the_same_org_id_are_two_organizations() -> None:
    one = await aexpand_organization_from_token(make_token(iss="https://lok.one", org="1"))
    two = await aexpand_organization_from_token(make_token(iss="https://lok.two", org="1"))

    assert one.pk != two.pk
    assert (one.issuer, one.org, two.issuer, two.org) == ("https://lok.one", "1", "https://lok.two", "1")
    assert (await aexpand_organization_from_token(make_token(iss="https://lok.one", org="1"))).pk == one.pk


def test_the_allow_list_names_the_issuer_too() -> None:
    settings = AuthentikateSettings(
        audience="*",
        issuers=[],
        static_tokens={"tok": StaticToken(sub="u", org="1")},
        allowed_organizations=["https://lok.one#1"],
    )
    # The static token's issuer is not lok.one: its org 1 is another organization.
    with pytest.raises(OrganizationNotAllowed, match="static_issuer#1"):
        asyncio.run(authenticate_token("tok", settings))


def test_a_provenance_token_carries_the_tasks_organization() -> None:
    claims = dict(
        iss="rekuest",
        aud=["alpaka"],
        sub="agent-user",
        act={"sub": "agent-user", "cid": "app"},
        iat=1750000000,
        exp=1750003600,
        jti="j",
        tsk="2",
        ptk="1",
        rtk="1",
        rcb="human",
        ahs="h",
        aha="sha256-canonical-v1",
        raw="raw",
    )
    assert ProvenanceToken.model_validate({**claims, "org": "https://lok.one#1"}).org == "https://lok.one#1"
    assert ProvenanceToken.model_validate(claims).org is None
