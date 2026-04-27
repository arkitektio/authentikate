"""Test that a Http request receives a broadcast from an HTTP mutation."""

import pytest
import asyncio
from uuid import uuid4
from unittest.mock import AsyncMock, patch

from test_project.asgi import application
from kante.testing import GraphQLHttpTestClient, GraphQLWebSocketTestClient
from django.conf import settings
from authentikate.expand import ExpandedTokenContext
from authentikate.models import Client, Membership, Organization, User


@pytest.mark.asyncio
async def test_user_query(db, valid_auth_headers, key_pair_str) -> None:
    """Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients

    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key

    http_client = GraphQLHttpTestClient(
        application=application, headers=valid_auth_headers
    )

    # Send the mutation via HTTP
    answer = await http_client.execute(
        query="""
        query {
            me  {
                sub
                activeOrganization {
                    id
                    slug
                }
            }
        }
        """,
    )

    assert answer["data"]["me"] is not None
    assert (
        answer["data"]["me"]["sub"] == "1"
    ), f"Expected '1', got {answer['data']['me']['sub']}"
    assert (
        answer["data"]["me"]["activeOrganization"] is not None
    ), f"Expected 'activeOrganization' to be not None, got {answer['data']['me']['activeOrganization']}"
    assert (
        answer["data"]["me"]["activeOrganization"]["slug"] == "kkk"
    ), f"Expected '1', got {answer['data']['me']['activeOrganization']['id']}"


@pytest.mark.asyncio
async def test_client_query(db, valid_auth_headers, key_pair_str) -> None:
    """Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients

    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key

    http_client = GraphQLHttpTestClient(
        application=application, headers=valid_auth_headers
    )

    # Send the mutation via HTTP
    answer = await http_client.execute(
        query="""
        query {
            client  {
                clientId
            }
        }
        """,
    )

    assert (
        answer["data"]["client"] is not None
    ), f"Expected 'client' to be not None, got {answer}"
    assert (
        answer["data"]["client"]["clientId"] == "XXXX"
    ), f"Expected 'XXXX', got {answer['data']['client']['clientId']}"


@pytest.mark.asyncio
async def test_http_query_uses_bundled_token_expansion(
    db, valid_auth_headers, key_pair_str
) -> None:
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key

    organization, _ = await Organization.objects.aget_or_create(slug="bundle-org")
    user, _ = await User.objects.aget_or_create(
        sub="1",
        iss="XXXX",
        defaults={
            "username": "bundle-user",
            "active_organization": organization,
        },
    )
    user.active_organization = organization
    await user.asave(update_fields=["active_organization"])
    client, _ = await Client.objects.aget_or_create(client_id="XXXX", iss="XXXX")
    membership, _ = await Membership.objects.aget_or_create(
        user=user,
        organization=organization,
        defaults={"roles": ["XXXX"]},
    )
    membership.roles = ["XXXX"]
    await membership.asave(update_fields=["roles"])

    http_client = GraphQLHttpTestClient(
        application=application, headers=valid_auth_headers
    )

    with (
        patch(
            "authentikate.expand.aexpand_token_context",
            new=AsyncMock(
                return_value=ExpandedTokenContext(
                    user=user,
                    client=client,
                    organization=organization,
                    membership=membership,
                )
            ),
        ) as bundled_expand,
        patch(
            "authentikate.expand.aexpand_user_from_token",
            new=AsyncMock(side_effect=AssertionError("expected bundled expansion")),
        ),
        patch(
            "authentikate.expand.aexpand_client_from_token",
            new=AsyncMock(side_effect=AssertionError("expected bundled expansion")),
        ),
        patch(
            "authentikate.expand.aexpand_organization_from_token",
            new=AsyncMock(side_effect=AssertionError("expected bundled expansion")),
        ),
        patch(
            "authentikate.expand.aexpand_membership",
            new=AsyncMock(side_effect=AssertionError("expected bundled expansion")),
        ),
    ):
        answer = await http_client.execute(
            query="""
            query {
                me {
                    sub
                }
            }
            """,
        )

    assert answer["data"]["me"]["sub"] == "1"
    bundled_expand.assert_awaited_once()
