"""
Supabase database operations.
Все IP адреса хранятся зашифрованными (Fernet AES).
Для поиска по IP используется SHA-256 хэш.

v2 (2026-05): большинство hot-path операций переведены на атомарные RPC
(activate_client_atomic, block_client_atomic, delete_client_atomic,
get_client_full_with_bans, add_ip_ban_idempotent). Сохраняется fallback
через env USE_RPC_ATOMIC=false на случай rollback.
"""

import os
import uuid
from datetime import datetime, date, timezone
from typing import Optional
from supabase import create_client, Client
from .crypto import encrypt_ip, decrypt_ip, hash_ip
from . import cache

_client: Optional[Client] = None
_PAGE_SIZE = 10000

_USE_RPC = os.environ.get("USE_RPC_ATOMIC", "true").lower() != "false"


def _db() -> Client:
    global _client
    if _client is None:
        _client = create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_KEY"],
        )
    return _client


def _fetch_all_paginated(query_builder_fn) -> list:
    all_rows = []
    offset = 0
    while True:
        query = query_builder_fn(offset, _PAGE_SIZE)
        result = query.execute()
        if not result.data:
            break
        all_rows.extend(result.data)
        if len(result.data) < _PAGE_SIZE:
            break
        offset += _PAGE_SIZE
    return all_rows


def _safe_decrypt(enc: Optional[str]) -> Optional[str]:
    if not enc:
        return None
    try:
        return decrypt_ip(enc)
    except Exception:
        return "decrypt_error"


# ═══════════════════════════════════════
# DASHBOARD STATS
# ═══════════════════════════════════════

def get_dashboard_stats() -> dict:
    try:
        result = _db().rpc("dashboard_stats", {}).execute()
        if result.data:
            return result.data
    except Exception as e:
        print(f"[dashboard_stats] RPC error: {e}")
    return {
        "total_clients": 0, "active_clients": 0, "blocked_clients": 0,
        "total_relays": 0, "active_relays": 0, "ip_bans": 0,
    }


# ═══════════════════════════════════════
# CLIENTS
# ═══════════════════════════════════════

def create_client_record(label: str = "", note: str = "") -> dict:
    token = uuid.uuid4().hex[:16]
    data = {"token": token, "label": label, "note": note}
    result = _db().table("clients").insert(data).execute()
    row = result.data[0]
    return {"id": row["id"], "token": row["token"], "label": label, "note": note}


def get_client_by_token(token: str) -> Optional[dict]:
    result = _db().table("clients").select("*").eq("token", token).execute()
    if not result.data:
        return None
    return _decrypt_client(result.data[0])


def get_client_by_id(client_id: int) -> Optional[dict]:
    result = _db().table("clients").select("*").eq("id", client_id).execute()
    if not result.data:
        return None
    return _decrypt_client(result.data[0])


def list_clients(include_blocked: bool = True) -> list[dict]:
    def _build(offset: int, limit: int):
        q = _db().table("clients").select("*").order("id").range(offset, offset + limit - 1)
        if not include_blocked:
            q = q.eq("is_blocked", False)
        return q

    rows = _fetch_all_paginated(_build)
    return [_decrypt_client(r) for r in rows]


def count_clients_on_ip(ip: str, exclude_client_id: int | None = None) -> int:
    ip_h = hash_ip(ip)
    try:
        result = _db().rpc(
            "count_clients_on_ip",
            {"p_ip_hash": ip_h, "p_exclude_client_id": exclude_client_id},
        ).execute()
        if result.data is not None:
            return int(result.data) if not isinstance(result.data, list) else int(result.data or 0)
        return 0
    except Exception as e:
        print(f"[count_clients_on_ip] RPC error: {e}")
        return 0


# ── activate ──

def activate_client(token: str, new_ip: str, user_agent: str = "") -> dict:
    """Активация по token. Атомарный RPC: 5 round-trip'ов → 1."""
    max_act = int(os.environ.get("MAX_ACTIVATIONS_PER_DAY", "10"))

    if _USE_RPC:
        try:
            result = _db().rpc("activate_client_atomic", {
                "p_token": token,
                "p_new_ip_enc": encrypt_ip(new_ip),
                "p_new_ip_hash": hash_ip(new_ip),
                "p_user_agent": user_agent or "",
                "p_max_per_day": max_act,
            }).execute()
            return _wrap_activation_response(result.data, new_ip)
        except Exception as e:
            print(f"[activate_client] RPC error: {e}, fallback to legacy")
    return _activate_client_legacy(token, new_ip, user_agent, max_act)


def activate_client_by_id(client_id: int, new_ip: str) -> dict:
    """Ручная активация по client_id и IP."""
    max_act = int(os.environ.get("MAX_ACTIVATIONS_PER_DAY", "10"))

    if _USE_RPC:
        try:
            result = _db().rpc("activate_client_by_id_atomic", {
                "p_client_id": client_id,
                "p_new_ip_enc": encrypt_ip(new_ip),
                "p_new_ip_hash": hash_ip(new_ip),
                "p_max_per_day": max_act,
            }).execute()
            return _wrap_activation_response(result.data, new_ip)
        except Exception as e:
            print(f"[activate_client_by_id] RPC error: {e}, fallback to legacy")
    return _activate_client_by_id_legacy(client_id, new_ip, max_act)


def _wrap_activation_response(data: dict, new_ip: str) -> dict:
    """Адаптирует JSONB-ответ RPC к форме, ожидаемой index.py."""
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


# ── legacy fallbacks ──

def _activate_client_legacy(token: str, new_ip: str, user_agent: str, max_act: int) -> dict:
    client = get_client_by_token(token)
    if not client:
        return {"error": "invalid_token"}
    if client["is_blocked"]:
        return {"error": "blocked"}
    ban = get_ip_ban(new_ip)
    if ban:
        return {"error": "ip_banned", "reason": ban["reason"]}

    today = date.today().isoformat()
    activations_today = client["_activations_today"]
    if client["_reset_date"] != today:
        activations_today = 0
    if max_act > 0 and activations_today >= max_act:
        return {"error": "daily_limit"}

    old_ip = client["current_ip"]
    if old_ip == new_ip:
        return {"status": "already_active", "client_id": client["id"], "new_ip": new_ip}

    old_ip_shared = False
    if old_ip:
        others = count_clients_on_ip(old_ip, exclude_client_id=client["id"])
        old_ip_shared = others > 0

    now = datetime.now(timezone.utc).isoformat()
    _db().table("clients").update({
        "previous_ip_enc": client["_raw_current_ip_enc"],
        "previous_ip_hash": client.get("_raw_current_ip_hash"),
        "current_ip_enc": encrypt_ip(new_ip),
        "current_ip_hash": hash_ip(new_ip),
        "last_activated_at": now,
        "activations_today": activations_today + 1,
        "activations_reset_date": today,
    }).eq("id", client["id"]).execute()

    _db().table("activation_log").insert({
        "client_id": client["id"],
        "ip_enc": encrypt_ip(new_ip),
        "ip_hash": hash_ip(new_ip),
        "user_agent": user_agent[:500] if user_agent else None,
    }).execute()

    return {
        "status": "activated", "client_id": client["id"],
        "old_ip": old_ip, "new_ip": new_ip, "old_ip_shared": old_ip_shared,
    }


def _activate_client_by_id_legacy(client_id: int, new_ip: str, max_act: int) -> dict:
    client = get_client_by_id(client_id)
    if not client:
        return {"error": "client_not_found"}
    if client["is_blocked"]:
        return {"error": "blocked"}
    ban = get_ip_ban(new_ip)
    if ban:
        return {"error": "ip_banned", "reason": ban["reason"]}

    today = date.today().isoformat()
    activations_today = client["_activations_today"]
    if client["_reset_date"] != today:
        activations_today = 0
    if max_act > 0 and activations_today >= max_act:
        return {"error": "daily_limit"}

    old_ip = client["current_ip"]
    if old_ip == new_ip:
        return {"status": "already_active", "client_id": client["id"], "new_ip": new_ip}

    old_ip_shared = False
    if old_ip:
        others = count_clients_on_ip(old_ip, exclude_client_id=client["id"])
        old_ip_shared = others > 0

    now = datetime.now(timezone.utc).isoformat()
    _db().table("clients").update({
        "previous_ip_enc": client["_raw_current_ip_enc"],
        "previous_ip_hash": client.get("_raw_current_ip_hash"),
        "current_ip_enc": encrypt_ip(new_ip),
        "current_ip_hash": hash_ip(new_ip),
        "last_activated_at": now,
        "activations_today": activations_today + 1,
        "activations_reset_date": today,
    }).eq("id", client["id"]).execute()

    _db().table("activation_log").insert({
        "client_id": client["id"],
        "ip_enc": encrypt_ip(new_ip),
        "ip_hash": hash_ip(new_ip),
        "user_agent": "manual_bot_activation",
    }).execute()

    return {
        "status": "activated", "client_id": client["id"],
        "old_ip": old_ip, "new_ip": new_ip, "old_ip_shared": old_ip_shared,
    }


# ── block / delete / full ──

def block_client(client_id: int, blocked: bool = True) -> Optional[dict]:
    """Возвращает обновлённый клиент с current_ip_banned/previous_ip_banned/current_ip_shared."""
    if _USE_RPC:
        try:
            result = _db().rpc("block_client_atomic", {
                "p_client_id": client_id, "p_blocked": blocked,
            }).execute()
            data = result.data
            if not data or "error" in data:
                return None
            return _decrypt_jsonb_client(data)
        except Exception as e:
            print(f"[block_client] RPC error: {e}, fallback")

    _db().table("clients").update({"is_blocked": blocked}).eq("id", client_id).execute()
    client = get_client_by_id(client_id)
    if client:
        client["current_ip_banned"] = bool(client["current_ip"]) and is_ip_banned(client["current_ip"])
        client["previous_ip_banned"] = bool(client["previous_ip"]) and is_ip_banned(client["previous_ip"])
        if client["current_ip"]:
            others = count_clients_on_ip(client["current_ip"], exclude_client_id=client_id)
            client["current_ip_shared"] = others > 0
        else:
            client["current_ip_shared"] = False
    return client


def delete_client(client_id: int) -> Optional[dict]:
    """Возвращает {deleted, id, current_ip, current_ip_shared} либо None."""
    if _USE_RPC:
        try:
            result = _db().rpc("delete_client_atomic", {
                "p_client_id": client_id,
            }).execute()
            data = result.data
            if not data or "error" in data:
                return None
            return {
                "id": data["id"],
                "current_ip": _safe_decrypt(data.get("current_ip_enc")),
                "current_ip_shared": bool(data.get("current_ip_shared", False)),
            }
        except Exception as e:
            print(f"[delete_client] RPC error: {e}, fallback")

    client = get_client_by_id(client_id)
    if not client:
        return None
    _db().table("activation_log").delete().eq("client_id", client_id).execute()
    _db().table("clients").delete().eq("id", client_id).execute()
    others = count_clients_on_ip(client["current_ip"]) if client["current_ip"] else 0
    return {
        "id": client_id,
        "current_ip": client["current_ip"],
        "current_ip_shared": others > 0,
    }


def get_client_full(client_id: int) -> Optional[dict]:
    """Клиент + флаги бана + текущий rate-limit. 3 запроса → 1."""
    if _USE_RPC:
        try:
            result = _db().rpc("get_client_full_with_bans", {
                "p_client_id": client_id,
            }).execute()
            data = result.data
            if not data or "error" in data:
                return None
            return _decrypt_jsonb_client(data)
        except Exception as e:
            print(f"[get_client_full] RPC error: {e}, fallback")

    client = get_client_by_id(client_id)
    if not client:
        return None
    client["current_ip_banned"] = bool(client["current_ip"]) and is_ip_banned(client["current_ip"])
    client["previous_ip_banned"] = bool(client["previous_ip"]) and is_ip_banned(client["previous_ip"])
    return client


def _decrypt_jsonb_client(data: dict) -> dict:
    """JSONB из RPC → обычный словарь клиента с расшифрованными IP."""
    return {
        "id": data["id"],
        "token": data.get("token"),
        "label": data.get("label", ""),
        "note": data.get("note", ""),
        "current_ip": _safe_decrypt(data.get("current_ip_enc")),
        "previous_ip": _safe_decrypt(data.get("previous_ip_enc")),
        "last_activated_at": data.get("last_activated_at"),
        "activations_today": data.get("activations_today", 0),
        "is_blocked": bool(data.get("is_blocked", False)),
        "created_at": data.get("created_at"),
        "current_ip_banned": bool(data.get("current_ip_banned", False)),
        "previous_ip_banned": bool(data.get("previous_ip_banned", False)),
        "current_ip_shared": bool(data.get("current_ip_shared", False)),
        "rate_limit": data.get("rate_limit"),
    }


# ── activation log ──

def delete_activation_logs(client_id: int) -> int:
    result = (
        _db().table("activation_log")
        .delete().eq("client_id", client_id).execute()
    )
    return len(result.data or [])


def get_activation_logs(client_id: int, limit: int = 50) -> list[dict]:
    result = (
        _db().table("activation_log")
        .select("*").eq("client_id", client_id)
        .order("created_at", desc=True).limit(limit).execute()
    )
    logs = []
    for r in result.data:
        logs.append({
            "id": r["id"],
            "ip": _safe_decrypt(r.get("ip_enc")),
            "user_agent": r.get("user_agent"),
            "created_at": r["created_at"],
        })
    return logs


def get_all_active_ips() -> list[str]:
    def _build(offset: int, limit: int):
        return (
            _db().table("clients")
            .select("current_ip_enc")
            .eq("is_blocked", False)
            .not_.is_("current_ip_enc", "null")
            .order("id")
            .range(offset, offset + limit - 1)
        )

    rows = _fetch_all_paginated(_build)
    ips = []
    for r in rows:
        try:
            ips.append(decrypt_ip(r["current_ip_enc"]))
        except Exception:
            pass
    return ips


# ── decrypt + search ──

def _decrypt_client(row: dict) -> dict:
    current_ip = _safe_decrypt(row.get("current_ip_enc"))
    previous_ip = _safe_decrypt(row.get("previous_ip_enc"))
    return {
        "id": row["id"],
        "token": row["token"],
        "label": row["label"],
        "note": row.get("note", ""),
        "current_ip": current_ip,
        "previous_ip": previous_ip,
        "last_activated_at": row["last_activated_at"],
        "activations_today": row["activations_today"],
        "is_blocked": row["is_blocked"],
        "created_at": row["created_at"],
        "_activations_today": row["activations_today"],
        "_reset_date": row.get("activations_reset_date"),
        "_raw_current_ip_enc": row.get("current_ip_enc"),
        "_raw_current_ip_hash": row.get("current_ip_hash"),
    }


def search_clients_by_ip(ip: str, include_log_history: bool = True) -> list[dict]:
    ip_h = hash_ip(ip)
    try:
        result = _db().rpc(
            "find_clients_by_ip",
            {"p_ip_hash": ip_h, "p_include_log_history": include_log_history},
        ).execute()
    except Exception as e:
        print(f"[search_clients_by_ip] RPC error: {e}")
        return []

    rows = result.data or []
    clients = []
    for row in rows:
        match_source = row.pop("match_source", None)
        client = _decrypt_client(row)
        client["match_source"] = match_source
        clients.append(client)
    return clients


# ═══════════════════════════════════════
# IP BLACKLIST
# ═══════════════════════════════════════

def add_ip_ban(ip: str, reason: str = "") -> dict:
    """Идемпотентный INSERT через RPC (без race-condition)."""
    ip_h = hash_ip(ip)
    if _USE_RPC:
        try:
            result = _db().rpc("add_ip_ban_idempotent", {
                "p_ip_hash": ip_h,
                "p_ip_enc": encrypt_ip(ip),
                "p_reason": reason,
            }).execute()
            data = result.data or {}
            return {
                "id": data.get("id"),
                "ip": ip,
                "reason": reason,
                "already_exists": bool(data.get("already_exists", False)),
            }
        except Exception as e:
            print(f"[add_ip_ban] RPC error: {e}, fallback")

    existing = (
        _db().table("ip_blacklist").select("id").eq("ip_hash", ip_h).execute()
    )
    if existing.data:
        return {"id": existing.data[0]["id"], "already_exists": True}

    result = _db().table("ip_blacklist").insert({
        "ip_hash": ip_h, "ip_enc": encrypt_ip(ip), "reason": reason,
    }).execute()
    row = result.data[0]
    return {"id": row["id"], "ip": ip, "reason": reason, "already_exists": False}


def remove_ip_ban(ban_id: int) -> bool:
    result = _db().table("ip_blacklist").delete().eq("id", ban_id).execute()
    return len(result.data) > 0


def remove_ip_ban_by_ip(ip: str) -> bool:
    ip_h = hash_ip(ip)
    result = _db().table("ip_blacklist").delete().eq("ip_hash", ip_h).execute()
    return len(result.data) > 0


def is_ip_banned(ip: str) -> bool:
    ip_h = hash_ip(ip)
    result = (
        _db().table("ip_blacklist").select("id", count="exact")
        .eq("ip_hash", ip_h).execute()
    )
    return (result.count or 0) > 0


def get_ip_ban(ip: str) -> Optional[dict]:
    ip_h = hash_ip(ip)
    result = _db().table("ip_blacklist").select("*").eq("ip_hash", ip_h).execute()
    if not result.data:
        return None
    row = result.data[0]
    return {
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "reason": row["reason"],
        "created_at": row["created_at"],
    }


def get_ip_ban_by_id(ban_id: int) -> Optional[dict]:
    result = _db().table("ip_blacklist").select("*").eq("id", ban_id).execute()
    if not result.data:
        return None
    row = result.data[0]
    return {
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "reason": row["reason"],
        "created_at": row["created_at"],
    }


def list_ip_bans() -> list[dict]:
    def _build(offset: int, limit: int):
        return (
            _db().table("ip_blacklist").select("*")
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
        )
    rows = _fetch_all_paginated(_build)
    return [{
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "reason": row["reason"],
        "created_at": row["created_at"],
    } for row in rows]


def list_ip_bans_paginated(page: int = 0, per_page: int = 20,
                           search: str | None = None) -> dict:
    query = _db().table("ip_blacklist").select("*", count="exact")
    if search and search.strip():
        ip_h = hash_ip(search.strip())
        query = query.eq("ip_hash", ip_h)

    offset = page * per_page
    result = (
        query.order("created_at", desc=True)
        .range(offset, offset + per_page - 1)
        .execute()
    )
    items = [{
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "reason": row["reason"],
        "created_at": row["created_at"],
    } for row in (result.data or [])]
    total = result.count or 0
    return {
        "items": items, "total": total,
        "page": page, "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


# ═══════════════════════════════════════
# RELAYS (с TTL-кэшем)
# ═══════════════════════════════════════

_RELAYS_CACHE_TTL = float(os.environ.get("RELAYS_CACHE_TTL", "15"))


def add_relay(name: str, host: str, agent_port: int = 7580,
              agent_secret: str = "") -> dict:
    data = {
        "name": name, "host": host,
        "agent_port": agent_port, "agent_secret": agent_secret,
    }
    result = _db().table("relays").insert(data).execute()
    cache.invalidate("relays:")
    return result.data[0]


def list_relays(fields: str = "full") -> list[dict]:
    """fields='full' | 'basic'. Кэшируется на RELAYS_CACHE_TTL секунд."""
    key = f"relays:{fields}"
    cached_value = cache.get(key)
    if cached_value is not None:
        return cached_value

    if fields == "basic":
        cols = "id,name,host,agent_port,is_active,is_synced,last_health_at"
    else:
        cols = "*"
    result = _db().table("relays").select(cols).order("id").execute()
    cache.set(key, result.data, ttl=_RELAYS_CACHE_TTL)
    return result.data


def get_active_relays() -> list[dict]:
    cached_value = cache.get("relays:active")
    if cached_value is not None:
        return cached_value
    result = (
        _db().table("relays").select("*").eq("is_active", True).execute()
    )
    cache.set("relays:active", result.data, ttl=_RELAYS_CACHE_TTL)
    return result.data


def delete_relay(relay_id: int) -> bool:
    result = _db().table("relays").delete().eq("id", relay_id).execute()
    cache.invalidate("relays:")
    return len(result.data) > 0


def toggle_relay(relay_id: int, active: bool) -> Optional[dict]:
    _db().table("relays").update({"is_active": active}).eq("id", relay_id).execute()
    cache.invalidate("relays:")
    result = _db().table("relays").select("*").eq("id", relay_id).execute()
    return result.data[0] if result.data else None


def mark_relay_synced(relay_id: int, synced: bool):
    _db().table("relays").update({"is_synced": synced}).eq("id", relay_id).execute()
    cache.invalidate("relays:")


def update_relay_health(relay_id: int, health_data: dict):
    _db().table("relays").update({
        "last_health": health_data,
        "last_health_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", relay_id).execute()
    cache.invalidate("relays:")


# ═══════════════════════════════════════
# RATE LIMITS
# ═══════════════════════════════════════

def add_rate_limit(ip: str, mbps: float,
                   expires_at: Optional[str] = None,
                   reason: str = "",
                   client_id: Optional[int] = None) -> dict:
    """UPSERT в rate_limits. Возвращает финальную запись."""
    ip_h = hash_ip(ip)
    payload = {
        "ip_hash": ip_h,
        "ip_enc": encrypt_ip(ip),
        "mbps": float(mbps),
        "reason": reason or "",
        "expires_at": expires_at,
        "client_id": client_id,
    }
    result = (
        _db().table("rate_limits")
        .upsert(payload, on_conflict="ip_hash")
        .execute()
    )
    row = result.data[0]
    return {
        "id": row["id"],
        "ip": ip,
        "mbps": float(row["mbps"]),
        "reason": row.get("reason", ""),
        "expires_at": row.get("expires_at"),
        "client_id": row.get("client_id"),
        "created_at": row.get("created_at"),
    }


def remove_rate_limit_by_ip(ip: str) -> bool:
    ip_h = hash_ip(ip)
    result = _db().table("rate_limits").delete().eq("ip_hash", ip_h).execute()
    return len(result.data) > 0


def get_rate_limit(ip: str) -> Optional[dict]:
    ip_h = hash_ip(ip)
    result = _db().table("rate_limits").select("*").eq("ip_hash", ip_h).execute()
    if not result.data:
        return None
    row = result.data[0]
    return {
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "mbps": float(row["mbps"]),
        "reason": row.get("reason", ""),
        "expires_at": row.get("expires_at"),
        "client_id": row.get("client_id"),
        "created_at": row["created_at"],
    }


def list_rate_limits() -> list[dict]:
    def _build(offset: int, limit: int):
        return (
            _db().table("rate_limits").select("*")
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
        )
    rows = _fetch_all_paginated(_build)
    return [{
        "id": row["id"],
        "ip": _safe_decrypt(row["ip_enc"]),
        "mbps": float(row["mbps"]),
        "reason": row.get("reason", ""),
        "expires_at": row.get("expires_at"),
        "client_id": row.get("client_id"),
        "created_at": row["created_at"],
    } for row in rows]


def list_expired_rate_limits() -> list[dict]:
    """Для внешнего шедулера юзера: всё, что пора снять."""
    try:
        result = _db().rpc("get_expired_rate_limits", {}).execute()
    except Exception as e:
        print(f"[list_expired_rate_limits] RPC error: {e}")
        return []
    rows = result.data or []
    return [{
        "id": r["id"],
        "ip": _safe_decrypt(r["ip_enc"]),
        "mbps": float(r["mbps"]),
        "expires_at": r["expires_at"],
        "client_id": r.get("client_id"),
    } for r in rows]


# ═══════════════════════════════════════
# SYNC PAYLOAD (для startup-resync агента)
# ═══════════════════════════════════════

def get_sync_payload() -> dict:
    """Полный payload для агента: clients + rate_limits.
    IP расшифровываются на стороне Python."""
    try:
        result = _db().rpc("get_sync_payload", {}).execute()
    except Exception as e:
        print(f"[get_sync_payload] RPC error: {e}")
        return {"clients": [], "rate_limits": []}

    rows = result.data or []
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
                "expires_at": r.get("rate_limit_expires_at"),
                "client_id": r["client_id"],
            }

    return {"clients": clients, "rate_limits": list(rl_seen.values())}
