""" Test that a Http request receives a broadcast from an HTTP mutation."""

import pytest
import asyncio
from uuid import uuid4

from test_project.asgi import application
from kante.testing import GraphQLHttpTestClient, GraphQLWebSocketTestClient
from django.conf import settings

@pytest.mark.asyncio
async def test_user_query(db, valid_auth_headers, key_pair_str) -> None:
    """ Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients
    
    
    
    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key
    
    
    
    http_client = GraphQLHttpTestClient(application=application,
                                        headers=valid_auth_headers)
    
    
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
    assert answer["data"]["me"]["sub"] == "1", f"Expected '1', got {answer['data']['me']['sub']}"
    assert answer["data"]["me"]["activeOrganization"] is not None, f"Expected 'activeOrganization' to be not None, got {answer['data']['me']['activeOrganization']}"
    assert answer["data"]["me"]["activeOrganization"]["slug"] == "kkk", f"Expected '1', got {answer['data']['me']['activeOrganization']['id']}"
    
    
    
    
    
    
    
@pytest.mark.asyncio
async def test_client_query(db, valid_auth_headers, key_pair_str) -> None:
    """ Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients
    
    
    
    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key
    
    
    
    http_client = GraphQLHttpTestClient(application=application,
                                        headers=valid_auth_headers)
    
    
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
    
    assert answer["data"]["client"] is not None, f"Expected 'client' to be not None, got {answer}"
    assert answer["data"]["client"]["clientId"] == "XXXX", f"Expected 'XXXX', got {answer['data']['client']['clientId']}"