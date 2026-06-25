"""
PostgreSQL database operations (async psycopg3 + connection pool).
All IP addresses are stored encrypted (Fernet AES).
SHA-256 hash is used for IP search.

Hot-path operations - atomic SQL functions (see db/schema.sql):
activate_client_atomic, block_client_atomic, delete_client_atomic,
get_client_full_with_bans, add_ip_ban_idempotent, get_sync_payload,
find_clients_by_ip, count_clients_on_ip, dashboard_stats.
"""

import os
import uuid
import ipaddress
import socket
from datetime import datetime
from typing import Optional

from psycopg_pool import AsyncConnectionPool
from psycopg.rows import dict_row

from .crypto import encrypt_ip, decrypt_ip, hash_ip
from . import cache

_pool: Optional[AsyncConnectionPool] = None


def _get_pool() -> AsyncConnectionPool:
    global _pool
    if _pool is None:
        _pool = AsyncConnectionPool(
            os.environ["DATABASE_URL"],
            min_size=int(os.environ.get("DB_POOL_MIN", "1")),
            max_size=int(os.environ.get("DB_POOL_MAX", "10")),
            kwargs={"row_factory": dict_row},
            open=False,
        )
    return _pool


async def open_pool() -> None:
    pool = _get_pool()
    await pool.open()
    await pool.wait()


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def ping() -> bool:
    async with _get_pool().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT 1")
            await cur.fetchone()
    return True


async def _all(sql: str, params=None) -> list[dict]:
    async with _get_pool().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            return await cur.fetchall()


async def _one(sql: str, params=None) -> Optional[dict]:
    async with _get_pool().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            return await cur.fetchone()


async def _exec(sql: str, params=None) -> int:
    async with _get_pool().connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(sql, params)
            return cur.rowcount


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def _safe_decrypt(enc: Optional[str]) -> Optional[str]:
    if not enc:
        return None
    try:
        return decrypt_ip(enc)
    except Exception:
        return "decrypt_error"



async def get_dashboard_stats() -> dict:
    try:
        row = await _one("SELECT dashboard_stats() AS r")
        if row and row["r"]:
            return row["r"]
    except Exception as e:
        print(f"[dashboard_stats] error: {e}")
    return {
        "total_clients": 0, "active_clients": 0, "blocked_clients": 0,
        "total_relays": 0, "active_relays": 0, "ip_bans": 0,
    }



async def create_client_record(label: str = "") -> dict:
    token = uuid.uuid4().hex[:16]
    row = await _one(
        "INSERT INTO clients (token, label) VALUES (%s, %s) RETURNING id, token, label",
        (token, label),
    )
    if not row:
        raise ValueError("Failed to create client record")
    return {"id": row["id"], "token": row["token"], "label": label}


async def get_client_by_token(token: str) -> Optional[dict]:
    row = await _one("SELECT * FROM clients WHERE token = %s", (token,))
    return _decrypt_client(row) if row else None


async def get_client_by_id(client_id: int) -> Optional[dict]:
    row = await _one("SELECT * FROM clients WHERE id = %s", (client_id,))
    return _decrypt_client(row) if row else None


async def get_client_labels(ids: list[int]) -> dict[int, str]:
    """Batch-resolve client_id -> label. Array sent in query params, no URL limit."""
    if not ids:
        return {}
    unique_ids = list({int(i) for i in ids})
    rows = await _all(
        "SELECT id, label FROM clients WHERE id = ANY(%s)", (unique_ids,)
    )
    return {row["id"]: row.get("label", "") for row in rows}


async def list_clients_paginated(page: int = 0, per_page: int = 50,
                                 include_blocked: bool = True) -> dict:
    where = "" if include_blocked else "WHERE is_blocked = FALSE"
    offset = page * per_page
    rows = await _all(
        f"SELECT *, COUNT(*) OVER() AS _total FROM clients {where} "
        "ORDER BY id LIMIT %s OFFSET %s",
        (per_page, offset),
    )
    total = int(rows[0]["_total"]) if rows else 0
    items = [_decrypt_client(r) for r in rows]
    return {
        "items": items, "total": total,
        "page": page, "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


async def count_clients_on_ip(ip: str, exclude_client_id: int | None = None) -> int:
    ip_h = hash_ip(ip)
    try:
        row = await _one(
            "SELECT count_clients_on_ip(%s, %s) AS r",
            (ip_h, exclude_client_id),
        )
        return int(row["r"]) if row and row["r"] is not None else 0
    except Exception as e:
        print(f"[count_clients_on_ip] error: {e}")
        return 0



async def activate_client(token: str, new_ip: str) -> dict:
    """Activation by token. Atomic SQL function."""
    row = await _one(
        "SELECT activate_client_atomic(%s, %s, %s) AS r",
        (token, encrypt_ip(new_ip), hash_ip(new_ip)),
    )
    return _wrap_activation_response(row["r"] if row else None, new_ip)


async def activate_client_by_id(client_id: int, new_ip: str) -> dict:
    """Manual activation by client_id and IP."""
    row = await _one(
        "SELECT activate_client_by_id_atomic(%s, %s, %s) AS r",
        (client_id, encrypt_ip(new_ip), hash_ip(new_ip)),
    )
    return _wrap_activation_response(row["r"] if row else None, new_ip)


def _wrap_activation_response(data: dict, new_ip: str) -> dict:
    """Adapts the function's JSONB response to the format expected by index.py."""
    if not data or "error" in (data or {}):
        return data or {"error": "rpc_no_data"}

    if data.get("status") == "already_active":
        return {
            "status": "already_active",
            "client_id": data["client_id"],
            "new_ip": new_ip,
            "rate_limit": data.get("rate_limit"),
        }

    return {
        "status": "activated",
        "client_id": data["client_id"],
        "old_ip": _safe_decrypt(data.get("old_ip_enc")),
        "new_ip": new_ip,
        "old_ip_shared": bool(data.get("old_ip_shared", False)),
        "rate_limit": data.get("rate_limit"),
    }



async def block_client(client_id: int, blocked: bool = True) -> Optional[dict]:
    """Returns updated client with current_ip_banned/previous_ip_banned/current_ip_shared."""
    row = await _one(
        "SELECT block_client_atomic(%s, %s) AS r", (client_id, blocked)
    )
    data = row["r"] if row else None
    if not data or "error" in data:
        return None
    return _decrypt_jsonb_client(data)


async def delete_client(client_id: int) -> Optional[dict]:
    """Returns {id, current_ip, current_ip_shared} or None."""
    row = await _one("SELECT delete_client_atomic(%s) AS r", (client_id,))
    data = row["r"] if row else None
    if not data or "error" in data:
        return None
    return {
        "id": data["id"],
        "current_ip": _safe_decrypt(data.get("current_ip_enc")),
        "current_ip_shared": bool(data.get("current_ip_shared", False)),
    }


async def get_client_full(client_id: int) -> Optional[dict]:
    """Client + ban flags + current rate-limit in one call."""
    row = await _one("SELECT get_client_full_with_bans(%s) AS r", (client_id,))
    data = row["r"] if row else None
    if not data or "error" in data:
        return None
    return _decrypt_jsonb_client(data)


def _decrypt_jsonb_client(data: dict) -> dict:
    """JSONB from the function -> normal client dict with decrypted IPs."""
    return {
        "id": data["id"],
        "token": data.get("token"),
        "label": data.get("label", ""),
        "current_ip": _safe_decrypt(data.get("current_ip_enc")),
        "previous_ip": _safe_decrypt(data.get("previous_ip_enc")),
        "last_activated_at": data.get("last_activated_at"),
        "is_blocked": bool(data.get("is_blocked", False)),
        "created_at": data.get("created_at"),
        "current_ip_banned": bool(data.get("current_ip_banned", False)),
        "previous_ip_banned": bool(data.get("previous_ip_banned", False)),
        "current_ip_shared": bool(data.get("current_ip_shared", False)),
        "rate_limit": data.get("rate_limit"),
    }



async def delete_activation_logs(client_id: int) -> int:
    return await _exec("DELETE FROM activation_log WHERE client_id = %s", (client_id,))


async def get_activation_logs(client_id: int, limit: int = 50) -> list[dict]:
    rows = await _all(
        "SELECT id, ip_enc, created_at FROM activation_log "
        "WHERE client_id = %s ORDER BY created_at DESC LIMIT %s",
        (client_id, limit),
    )
    return [{
        "id": r["id"],
        "ip": _safe_decrypt(r.get("ip_enc")),
        "created_at": _iso(r["created_at"]),
    } for r in rows]


async def get_all_active_ips() -> list[str]:
    rows = await _all(
        "SELECT current_ip_enc FROM clients "
        "WHERE is_blocked = FALSE AND current_ip_enc IS NOT NULL ORDER BY id"
    )
    out = []
    for r in rows:
        try:
            out.append(decrypt_ip(r["current_ip_enc"]))
        except Exception:
            pass
    return out



def _decrypt_client(row: dict) -> dict:
    return {
        "id": row["id"],
        "token": row["token"],
        "label": row["label"],
        "current_ip": _safe_decrypt(row.get("current_ip_enc")),
        "previous_ip": _safe_decrypt(row.get("previous_ip_enc")),
        "last_activated_at": _iso(row["last_activated_at"]),
        "is_blocked": row["is_blocked"],
        "created_at": _iso(row["created_at"]),
    }


async def search_clients_by_ip(ip: str, include_log_history: bool = True) -> list[dict]:
    ip_h = hash_ip(ip)
    try:
        rows = await _all(
            "SELECT * FROM find_clients_by_ip(%s, %s)",
            (ip_h, include_log_history),
        )
    except Exception as e:
        print(f"[search_clients_by_ip] error: {e}")
        return []

    clients = []
    for row in rows:
        match_source = row.pop("match_source", None)
        client = _decrypt_client(row)
        client["match_source"] = match_source
        clients.append(client)
    return clients



async def add_ip_ban(ip: str, reason: str = "") -> dict:
    """Idempotent INSERT via function (no race-condition)."""
    ip_h = hash_ip(ip)
    row = await _one(
        "SELECT add_ip_ban_idempotent(%s, %s, %s) AS r",
        (ip_h, encrypt_ip(ip), reason),
    )
    data = row["r"] if row else {}
    return {
        "id": data.get("id"),
        "ip": ip,
        "reason": reason,
        "already_exists": bool(data.get("already_exists", False)),
    }


async def remove_ip_ban(ban_id: int) -> bool:
    return await _exec("DELETE FROM ip_blacklist WHERE id = %s", (ban_id,)) > 0


async def remove_ip_ban_by_ip(ip: str) -> bool:
    ip_h = hash_ip(ip)
    return await _exec("DELETE FROM ip_blacklist WHERE ip_hash = %s", (ip_h,)) > 0


async def is_ip_banned(ip: str) -> bool:
    ip_h = hash_ip(ip)
    row = await _one(
        "SELECT EXISTS(SELECT 1 FROM ip_blacklist WHERE ip_hash = %s) AS r", (ip_h,)
    )
    return bool(row["r"]) if row else False


async def get_ip_ban(ip: str) -> Optional[dict]:
    ip_h = hash_ip(ip)
    row = await _one("SELECT * FROM ip_blacklist WHERE ip_hash = %s", (ip_h,))
    if not row:
        return None
    return {
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "reason": row["reason"],
        "created_at": _iso(row["created_at"]),
    }


async def get_ip_ban_by_id(ban_id: int) -> Optional[dict]:
    row = await _one("SELECT * FROM ip_blacklist WHERE id = %s", (ban_id,))
    if not row:
        return None
    return {
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "reason": row["reason"],
        "created_at": _iso(row["created_at"]),
    }


async def list_ip_bans() -> list[dict]:
    rows = await _all("SELECT * FROM ip_blacklist ORDER BY created_at DESC")
    return [{
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "reason": row["reason"],
        "created_at": _iso(row["created_at"]),
    } for row in rows]


async def list_ip_bans_paginated(page: int = 0, per_page: int = 20,
                                 search: str | None = None) -> dict:
    offset = page * per_page
    if search and search.strip():
        ip_h = hash_ip(search.strip())
        rows = await _all(
            "SELECT *, COUNT(*) OVER() AS _total FROM ip_blacklist "
            "WHERE ip_hash = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (ip_h, per_page, offset),
        )
    else:
        rows = await _all(
            "SELECT *, COUNT(*) OVER() AS _total FROM ip_blacklist "
            "ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (per_page, offset),
        )
    total = int(rows[0]["_total"]) if rows else 0
    items = [{
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "reason": row["reason"],
        "created_at": _iso(row["created_at"]),
    } for row in rows]
    return {
        "items": items, "total": total,
        "page": page, "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


# RELAYS (with TTL cache)

_RELAYS_CACHE_TTL = float(os.environ.get("RELAYS_CACHE_TTL", "15"))


async def add_relay(name: str, host: str, agent_port: int = 7580,
                    agent_secret: str = "", agent_type: str = "full") -> dict:
    try:
        resolved_ip = socket.gethostbyname(host)
        ip = ipaddress.ip_address(resolved_ip)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            raise ValueError(f"Invalid host: {host} resolves to a local/private IP ({resolved_ip})")
    except socket.gaierror:
        raise ValueError(f"Invalid host: could not resolve {host}")
    except ValueError as e:
        if "Invalid host" in str(e):
            raise

    if agent_type not in ("full", "min"):
        raise ValueError(f"agent_type must be 'full' or 'min', got: {agent_type}")

    row = await _one(
        "INSERT INTO relays (name, host, agent_port, agent_secret, agent_type) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING *",
        (name, host, agent_port, agent_secret, agent_type),
    )
    if not row:
        raise ValueError("Failed to add relay")
    cache.invalidate("relays:")
    return row


async def list_relays(fields: str = "full") -> list[dict]:
    """fields='full' | 'basic'. Cached for RELAYS_CACHE_TTL seconds."""
    key = f"relays:{fields}"
    cached_value = cache.get(key)
    if cached_value is not None:
        return cached_value

    if fields == "basic":
        cols = "id, name, host, agent_port, is_active, is_synced, last_health_at"
    else:
        cols = "*"
    rows = await _all(f"SELECT {cols} FROM relays ORDER BY id")
    cache.set(key, rows, ttl=_RELAYS_CACHE_TTL)
    return rows


async def get_active_relays(agent_type: str | None = None) -> list[dict]:
    """
    agent_type=None   -> all active (for health-check, traffic, update_all)
    agent_type='full' -> only full (for whitelist/rate-limit fan-out)
    agent_type='min'  -> only min (if needed in the future)
    """
    key = f"relays:active:{agent_type or 'all'}"
    cached_value = cache.get(key)
    if cached_value is not None:
        return cached_value
    if agent_type:
        rows = await _all(
            "SELECT * FROM relays WHERE is_active = TRUE AND agent_type = %s ORDER BY id",
            (agent_type,),
        )
    else:
        rows = await _all("SELECT * FROM relays WHERE is_active = TRUE ORDER BY id")
    cache.set(key, rows, ttl=_RELAYS_CACHE_TTL)
    return rows


async def delete_relay(relay_id: int) -> bool:
    deleted = await _exec("DELETE FROM relays WHERE id = %s", (relay_id,)) > 0
    cache.invalidate("relays:")
    return deleted


async def toggle_relay(relay_id: int, active: bool) -> Optional[dict]:
    row = await _one(
        "UPDATE relays SET is_active = %s WHERE id = %s RETURNING *",
        (active, relay_id),
    )
    cache.invalidate("relays:")
    return row


async def mark_relay_synced(relay_id: int, synced: bool):
    await _exec("UPDATE relays SET is_synced = %s WHERE id = %s", (synced, relay_id))
    cache.invalidate("relays:")


async def update_relay_health(relay_id: int, health_data: dict):
    from psycopg.types.json import Jsonb
    await _exec(
        "UPDATE relays SET last_health = %s, last_health_at = NOW() WHERE id = %s",
        (Jsonb(health_data), relay_id),
    )
    cache.invalidate("relays:")



async def add_rate_limit(ip: str, mbps: float,
                         expires_at: Optional[str] = None,
                         reason: str = "",
                         client_id: Optional[int] = None) -> dict:
    """UPSERT in rate_limits. Returns the final record."""
    ip_h = hash_ip(ip)
    row = await _one(
        "INSERT INTO rate_limits (ip_hash, ip_enc, mbps, reason, expires_at, client_id) "
        "VALUES (%s, %s, %s, %s, %s::timestamptz, %s) "
        "ON CONFLICT (ip_hash) DO UPDATE SET "
        "  ip_enc = EXCLUDED.ip_enc, mbps = EXCLUDED.mbps, reason = EXCLUDED.reason, "
        "  expires_at = EXCLUDED.expires_at, client_id = EXCLUDED.client_id "
        "RETURNING id, mbps, reason, expires_at, client_id, created_at",
        (ip_h, encrypt_ip(ip), float(mbps), reason or "", expires_at, client_id),
    )
    return {
        "id": row["id"],
        "ip": ip,
        "mbps": float(row["mbps"]),
        "reason": row.get("reason", ""),
        "expires_at": _iso(row.get("expires_at")),
        "client_id": row.get("client_id"),
        "created_at": _iso(row.get("created_at")),
    }


async def remove_rate_limit_by_ip(ip: str) -> bool:
    ip_h = hash_ip(ip)
    return await _exec("DELETE FROM rate_limits WHERE ip_hash = %s", (ip_h,)) > 0


async def get_rate_limit(ip: str) -> Optional[dict]:
    ip_h = hash_ip(ip)
    row = await _one("SELECT * FROM rate_limits WHERE ip_hash = %s", (ip_h,))
    if not row:
        return None
    return {
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "mbps": float(row["mbps"]),
        "reason": row.get("reason", ""),
        "expires_at": _iso(row.get("expires_at")),
        "client_id": row.get("client_id"),
        "created_at": _iso(row["created_at"]),
    }


async def list_rate_limits_paginated(page: int = 0, per_page: int = 50) -> dict:
    offset = page * per_page
    rows = await _all(
        "SELECT *, COUNT(*) OVER() AS _total FROM rate_limits "
        "ORDER BY created_at DESC LIMIT %s OFFSET %s",
        (per_page, offset),
    )
    total = int(rows[0]["_total"]) if rows else 0
    items = [{
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "mbps": float(row["mbps"]),
        "reason": row.get("reason", ""),
        "expires_at": _iso(row.get("expires_at")),
        "client_id": row.get("client_id"),
        "created_at": _iso(row["created_at"]),
    } for row in rows]
    return {
        "items": items, "total": total,
        "page": page, "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


async def list_expired_rate_limits() -> list[dict]:
    """For user's external scheduler: everything to remove."""
    try:
        rows = await _all("SELECT * FROM get_expired_rate_limits()")
    except Exception as e:
        print(f"[list_expired_rate_limits] error: {e}")
        return []
    return [{
        "id": r["id"],
        "ip": _safe_decrypt(r["ip_enc"]),
        "mbps": float(r["mbps"]),
        "expires_at": _iso(r["expires_at"]),
        "client_id": r.get("client_id"),
    } for r in rows]


# SYNC PAYLOAD (for startup-resync agent)

async def get_sync_payload() -> dict:
    """Full payload for the agent: clients + rate_limits.
    IPs are decrypted on the Python side."""
    try:
        rows = await _all("SELECT * FROM get_sync_payload()")
    except Exception as e:
        print(f"[get_sync_payload] error: {e}")
        return {"clients": [], "rate_limits": []}

    clients = []
    rl_seen: dict[str, dict] = {}

    for r in rows:
        ip = _safe_decrypt(r["current_ip_enc"])
        if not ip or ip == "decrypt_error":
            continue
        clients.append({"client_id": r["client_id"], "ip": ip})

        if r.get("rate_limit_mbps") is not None:
            rl_seen[ip] = {
                "ip": ip,
                "mbps": float(r["rate_limit_mbps"]),
                "expires_at": _iso(r.get("rate_limit_expires_at")),
                "client_id": r["client_id"],
            }

    return {"clients": clients, "rate_limits": list(rl_seen.values())}
