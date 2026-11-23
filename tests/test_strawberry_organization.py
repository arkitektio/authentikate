"""Test that a Http request receives a broadcast from an HTTP mutation."""

import pytest
from django.conf import settings
from kante.testing import GraphQLHttpTestClient

from test_project.asgi import application
from tests.conftest import KeyPairStr


@pytest.mark.asyncio
async def test_organization_query(
    db: None, valid_auth_headers: dict[str, str], key_pair_str: KeyPairStr
) -> None:
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
            organization  {
                identifier
            }
        }
        """,
    )

    assert answer["data"]["organization"] is not None
    assert answer["data"]["organization"]["identifier"] == "XXXX#kkk", (
        f"Expected 'XXXX#kkk', got {answer['data']['organization']['identifier']}"
    )


@pytest.mark.asyncio
async def test_organization_query_static(
    db: None, valid_auth_headers: dict[str, str], key_pair_str: KeyPairStr
) -> None:
    """Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients

    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key

    # hallo was set as a static token

    http_client = GraphQLHttpTestClient(
        application=application, headers={"Authorization": "Bearer hallo"}
    )

    # Send the mutation via HTTP
    answer = await http_client.execute(
        query="""
        query {
            organization  {
                identifier
            }
        }
        """,
    )

    assert answer["data"]["organization"] is not None
    assert answer["data"]["organization"]["identifier"] == "lok#static_org", (
        f"Expected 'lok#static_org', got {answer['data']['organization']['identifier']}"
    )
