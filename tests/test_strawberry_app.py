""" Test that a Http request receives a broadcast from an HTTP mutation."""

import pytest
import asyncio
from uuid import uuid4

from test_project.asgi import application
from kante.testing import GraphQLHttpTestClient, GraphQLWebSocketTestClient
from django.conf import settings

@pytest.mark.asyncio
async def test_organization_query(db, valid_auth_headers, key_pair_str) -> None:
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
            organization  {
                slug
            }
        }
        """,
    )

    assert answer["data"]["organization"] is not None
    assert answer["data"]["organization"]["slug"] == "kkk", f"Expected 'kkk', got {answer['data']['organization']['slug']}"


    
    
@pytest.mark.asyncio
async def test_organization_query_static(db, valid_auth_headers, key_pair_str) -> None:
    """ Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients
    
    
    
    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key
    
    # hallo was set as a static token
    
    http_client = GraphQLHttpTestClient(application=application,
                                        headers={"Authorization": "Bearer hallo"})
    
    
    # Send the mutation via HTTP
    answer = await http_client.execute(
        query="""
        query {
            organization  {
                slug
            }
        }
        """,
    )

    assert answer["data"]["organization"] is not None
    assert answer["data"]["organization"]["slug"] == "static_org", f"Expected 'kkk', got {answer['data']['organization']['slug']}"


  