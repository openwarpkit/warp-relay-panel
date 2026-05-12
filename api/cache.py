"""
Простой TTL in-memory кэш — на инстанс serverless-контейнера.
На Vercel cold-start обнуляет кэш, что приемлемо: цель — снять нагрузку
с горячих эндпоинтов внутри одного инстанса (list_relays вызывается
из десятка хендлеров).
"""

import time
from typing import Any, Callable

_DEFAULT_TTL = 15.0  # сек

_store: dict[str, tuple[float, Any]] = {}


def get(key: str) -> Any | None:
    item = _store.get(key)
    if item is None:
        return None
    expires_at, value = item
    if time.time() >= expires_at:
        _store.pop(key, None)
        return None
    return value


def set(key: str, value: Any, ttl: float = _DEFAULT_TTL) -> None:
    _store[key] = (time.time() + ttl, value)


def invalidate(prefix: str) -> int:
    """Удаляет все ключи, начинающиеся с prefix. Возвращает количество."""
    keys = [k for k in _store if k.startswith(prefix)]
    for k in keys:
        _store.pop(k, None)
    return len(keys)


def cached(key: str, ttl: float = _DEFAULT_TTL):
    """Декоратор: кэширует возврат функции под ключом."""
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
