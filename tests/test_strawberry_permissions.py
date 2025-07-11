""" Test that a Http request receives a broadcast from an HTTP mutation."""

import pytest
import asyncio
from uuid import uuid4

from test_project.asgi import application
from kante.testing import GraphQLHttpTestClient, GraphQLWebSocketTestClient
from django.conf import settings

@pytest.mark.asyncio
async def test_write_should_fail(db, valid_auth_headers, key_pair_str) -> None:
    """ Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients
    
    
    
    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key
    
    
    
    http_client = GraphQLHttpTestClient(application=application,
                                        headers=valid_auth_headers)
    
    
    # Send the mutation via HTTP:
    answer = await http_client.execute(
        query="""
        mutation {
            requireWrite
        }
        """,
    )
    
    
    
    
    assert answer["data"] is None, f"Expected 'requireWrite' to be  None, got {answer}"
    assert answer["errors"], f"Expected errors, got {answer['data']}"
    
    
@pytest.mark.asyncio
async def test_write_read_should_pass(db, valid_auth_headers, key_pair_str) -> None:
    """ Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients
    
    
    
    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key
    
    
    
    http_client = GraphQLHttpTestClient(application=application,
                                        headers=valid_auth_headers)
    
    
    # Send the mutation via HTTP:
    answer = await http_client.execute(
        query="""
        mutation {
            requireRead
        }
        """,
    )
    
    
    
    
    assert answer["data"]["requireRead"] is not None, f"Expected 'requireRead' to be not None, got {answer}"
    
    
    
    
    
    
