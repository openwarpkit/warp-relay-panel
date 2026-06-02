"""
Simple TTL in-memory cache per serverless container instance.
Vercel cold-starts reset the cache, which is acceptable since the goal
is to reduce load on hot endpoints within a single instance.
"""

import time
from typing import Any, Callable
from collections import OrderedDict

_DEFAULT_TTL = 15.0  # seconds

# OrderedDict to simulate LRU. maxsize is 1000.
_store: OrderedDict[str, tuple[float, Any]] = OrderedDict()


def get(key: str) -> Any | None:
    item = _store.get(key)
    if item is None:
        return None
    expires_at, value = item
    if time.time() >= expires_at:
        _store.pop(key, None)
        return None
    
    # move to end (mark as recently used)
    _store.move_to_end(key)
    return value


def set(key: str, value: Any, ttl: float = _DEFAULT_TTL) -> None:
    if key in _store:
        _store.pop(key) # remove so we can push to end
        
    _store[key] = (time.time() + ttl, value)
    
    # Enforce strict maximum size (LRU eviction)
    while len(_store) > 1000:
        # pop from the beginning (oldest / least recently used)
        _store.popitem(last=False)


def invalidate(prefix: str) -> int:
    """Removes all keys starting with prefix. Returns the count."""
    keys = [k for k in _store if k.startswith(prefix)]
    for k in keys:
        _store.pop(k, None)
    return len(keys)


def cached(key: str, ttl: float = _DEFAULT_TTL):
    """Decorator: caches function return value under key."""
    def decorator(fn: Callable):
        def wrapper(*args, **kwargs):
            cached_value = get(key)
            if cached_value is not None:
                return cached_value
            value = fn(*args, **kwargs)
            set(key, value, ttl)
            return value
        return wrapper
    return decorator
