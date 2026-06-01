import time
import pytest
import asyncio
import api.cache

@pytest.fixture(autouse=True)
def reset_cache():
    api.cache._store.clear()
    yield

@pytest.mark.asyncio
async def test_ttl_cache_set_and_get():
    # Test simple set and get
    api.cache.set("foo", "bar", ttl=1)
    assert api.cache.get("foo") == "bar"
    
    # Test missing key
    assert api.cache.get("missing") is None

@pytest.mark.asyncio
async def test_ttl_cache_expiration():
    api.cache.set("expiring", "data", ttl=0.1)
    assert api.cache.get("expiring") == "data"
    
    # Wait for expiration
    await asyncio.sleep(0.2)
    assert api.cache.get("expiring") is None

@pytest.mark.asyncio
async def test_ttl_cache_invalidate():
    api.cache.set("prefix_1", 1)
    api.cache.set("prefix_2", 2)
    api.cache.set("other", 3)
    
    api.cache.invalidate("prefix_")
    
    assert api.cache.get("prefix_1") is None
    assert api.cache.get("prefix_2") is None
    assert api.cache.get("other") == 3

