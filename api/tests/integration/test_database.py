import pytest
from api import database

@pytest.mark.asyncio
async def test_list_clients(mock_db):
    await database.open_pool()
    try:
        result = await database.list_clients_paginated()
        assert isinstance(result, dict)
        assert isinstance(result["items"], list)
    finally:
        await database.close_pool()

@pytest.mark.asyncio
async def test_get_active_relays(mock_db):
    await database.open_pool()
    try:
        relays = await database.get_active_relays()
        assert isinstance(relays, list)
    finally:
        await database.close_pool()
