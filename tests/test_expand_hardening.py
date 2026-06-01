import pytest
from typing import cast

from authentikate.base_models import JWTToken
from authentikate.errors import BlockedMembership, MissingActiveOrganization
from authentikate.expand import aexpand_membership, aexpand_organization_from_token
from authentikate.models import Membership, Organization, User
from authentikate.protocols import OrganizationModel, UserModel


def build_token(**overrides: object) -> JWTToken:
    payload = {
        "sub": "1",
        "iss": "test-issuer",
        "exp": 2000000000,
        "client_id": "client-1",
        "preferred_username": "user-1",
        "roles": ["reader"],
        "scope": "read",
        "iat": 1000000000,
        "raw": "raw-token",
        "active_org": "org-1",
    }
    payload.update(overrides)
    return JWTToken.model_validate(payload)


@pytest.mark.asyncio
async def test_aexpand_organization_requires_active_org() -> None:
    with pytest.raises(MissingActiveOrganization, match="active organization"):
        await aexpand_organization_from_token(build_token(active_org=None))


@pytest.mark.asyncio
async def test_aexpand_membership_rejects_blocked_membership(db) -> None:
    organization, _ = await Organization.objects.aget_or_create(slug="org-1")
    user, _ = await User.objects.aget_or_create(
        username="user-1",
        sub="1",
        iss="test-issuer",
    )
    await Membership.objects.aupdate_or_create(
        user=user,
        organization=organization,
        defaults={"roles": [], "blocked": True},
    )

    with pytest.raises(BlockedMembership, match="Membership is blocked"):
        await aexpand_membership(
            cast(UserModel, user),
            cast(OrganizationModel, organization),
            build_token(),
        )