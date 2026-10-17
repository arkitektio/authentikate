""" Test that a Http request receives a broadcast from an HTTP mutation."""

import pytest
import asyncio
from uuid import uuid4

from test_project.asgi import application
from kante.testing import GraphQLHttpTestClient, GraphQLWebSocketTestClient
from django.conf import settings

@pytest.mark.asyncio
async def test_str_channel_subscription_receives_broadcast_from_ws(db, valid_jwt, key_pair_str) -> None:
    """ Test that a WebSocket subscription receives a broadcast from an HTTP mutation."""
    # Initialize both clients
    
    
    
    # Set the public key in settings
    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key
    
    
    
    ws_client = GraphQLWebSocketTestClient(application=application,
                                        connection_params={"token": valid_jwt})
    
    
    # Send the mutation via HTTP
    async for answer in ws_client.subscribe(
            query="""
            subscription {
                yieldUser { 
                    sub
                }
            }
            """,
        ):
        
        assert answer["data"]["yieldUser"] is not None
        assert answer["data"]["yieldUser"]["sub"] == "1", f"Expected '1', got {answer['data']['yieldUser']['sub']}"
        
    
    
    
    
    
    


@pytest.mark.asyncio
async def test_an_errored_subscription_closes_cleanly(db, valid_jwt, key_pair_str) -> None:
    """A subscription that fails, then a disconnect, tears down without an error.

    The operation's stream is closed from another task on disconnect, so the auth
    context variables are released in a context that never set them.
    """
    import json

    settings.AUTHENTIKATE["ISSUERS"][0]["public_key"] = key_pair_str.public_key
    client = GraphQLWebSocketTestClient(application=application, connection_params={"token": valid_jwt})
    await client.connect()
    await client.communicator.send_input(
        {"type": "websocket.receive", "text": json.dumps({"id": "1", "type": "start", "payload": {"query": "subscription { nope }"}})}
    )
    answer = json.loads((await client.communicator.receive_output(timeout=2))["text"])
    assert answer["type"] in ("error", "data")

    await client.communicator.send_input({"type": "websocket.disconnect", "code": 1000})
    await client.communicator.wait(timeout=1)  # raises whatever the application raised
