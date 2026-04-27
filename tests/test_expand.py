from unittest.mock import AsyncMock, patch

from authentikate.decode import decode_token
from authentikate.expand import aexpand_token_context
from authentikate.models import Membership, Organization, User
import pytest


def test_authenticate_token(db, valid_jwt, valid_settings):
    token = decode_token(valid_jwt, valid_settings)
    assert token.sub == "1", "User ID should be 1"
    assert token.client_id == "XXXX", "Client ID should be 'XXXX'"


@pytest.mark.asyncio
async def test_aexpand_token_context_creates_related_models(
    db, valid_jwt, valid_settings
):
    token = decode_token(valid_jwt, valid_settings)

    expanded = await aexpand_token_context(token)

    assert expanded.user.sub == token.sub
    assert expanded.user.active_organization_id == expanded.organization.id
    assert expanded.client.client_id == token.client_id
    assert expanded.membership.user_id == expanded.user.id
    assert expanded.membership.organization_id == expanded.organization.id
    assert await Organization.objects.acount() == 1
    assert await Membership.objects.acount() == 1


@pytest.mark.asyncio
async def test_aexpand_token_context_resolves_organization_once(
    db, valid_jwt, valid_settings
):
    token = decode_token(valid_jwt, valid_settings)
    original_get_or_create = Organization.objects.aget_or_create

    async def tracked_get_or_create(*args, **kwargs):
        return await original_get_or_create(*args, **kwargs)

    mocked_get_or_create = AsyncMock(side_effect=tracked_get_or_create)

    with patch(
        "authentikate.expand.models.Organization.objects.aget_or_create",
        new=mocked_get_or_create,
    ):
        expanded = await aexpand_token_context(token)

    assert expanded.user.active_organization_id == expanded.organization.id
    assert mocked_get_or_create.await_count == 1
