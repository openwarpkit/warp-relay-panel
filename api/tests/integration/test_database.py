import pytest
from api import database

def test_list_clients(mock_db):
    """
    Test that will only run if mock_db is configured.
    Currently skipped because TEST_SUPABASE_URL is not provided.
    """
    result = database.list_clients_paginated()
    assert isinstance(result, dict)
    assert isinstance(result["items"], list)

def test_get_active_relays(mock_db):
    relays = database.get_active_relays()
    assert isinstance(relays, list)
