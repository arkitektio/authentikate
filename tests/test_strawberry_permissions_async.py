"""Test that a Http request receives a broadcast from an HTTP mutation."""

import pytest
from django.conf import settings
from kante.testing import GraphQLHttpTestClient

from test_project.asgi import application
from tests.conftest import KeyPairStr


@pytest.mark.asyncio
async def test_write_should_fail(
    db: None, valid_auth_headers: dict[str, str], key_pair_str: KeyPairStr
) -> None:
    """Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients

    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key

    http_client = GraphQLHttpTestClient(
        application=application, headers=valid_auth_headers
    )

    # Send the mutation via HTTP:
    answer = await http_client.execute(
        query="""
        mutation {
            asyncRequireWrite
        }
        """,
    )

    assert answer["data"] is None, f"Expected 'requireWrite' to be  None, got {answer}"
    assert answer["errors"], f"Expected errors, got {answer['data']}"
