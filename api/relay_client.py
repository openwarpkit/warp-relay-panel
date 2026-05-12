"""
HTTP-клиент для relay-агентов.
"""

import asyncio
import ipaddress
import logging
import httpx
from . import database as db

logger = logging.getLogger("relay_client")

AGENT_TIMEOUT = 10.0
SYNC_TIMEOUT = 30.0  # Для /whitelist/sync (большой payload)


def _validate_ipv4(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        raise ValueError(f"IPv6 not supported: {ip}")
    return str(addr)


def _agent_url(relay: dict) -> str:
    return f"http://{relay['host']}:{relay['agent_port']}"


def _agent_headers(relay: dict) -> dict:
    secret = relay.get("agent_secret") or ""
    return {"X-Agent-Key": secret, "Content-Type": "application/json"}


async def _agent_request(relay: dict, method: str, path: str,
                         json_data: dict = None,
                         timeout: float = AGENT_TIMEOUT) -> tuple[bool, dict]:
    url = f"{_agent_url(relay)}{path}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.request(
                method, url,
                headers=_agent_headers(relay),
                json=json_data,
            )
            data = resp.json()
            if resp.status_code >= 400:
                logger.warning("[%s] %s %s → %d: %s",
                               relay["name"], method, path, resp.status_code, data)
                return False, data
            return True, data
    except httpx.TimeoutException:
        msg = f"[{relay['name']}] timeout: {method} {path}"
        logger.error(msg)
        return False, {"error": msg}
    except Exception as e:
        msg = f"[{relay['name']}] error: {e}"
        logger.error(msg)
        return False, {"error": msg}


# ═══════════════════════════════════════
# WHITELIST OPERATIONS
# ═══════════════════════════════════════

async def add_ip(new_ip: str, old_ip: str | None = None,
                 client_id: int | None = None) -> dict:
    try:
        new_ip = _validate_ipv4(new_ip)
        if old_ip:
            old_ip = _validate_ipv4(old_ip)
    except ValueError as e:
        logger.error("IP validation: %s", e)
        return {"error": str(e)}

    relays = db.get_active_relays()
    if not relays:
        return {"error": "no_active_relays"}

    results = {}

    async def _process(relay):
        payload = {"new_ip": new_ip}
        if old_ip:
            payload["old_ip"] = old_ip
        if client_id is not None:
            payload["client_id"] = client_id
        ok, data = await _agent_request(relay, "POST", "/whitelist/update", payload)
        db.mark_relay_synced(relay["id"], ok)
        results[relay["name"]] = {"ok": ok, **data}

    await asyncio.gather(*[_process(r) for r in relays], return_exceptions=True)
    return results


async def remove_ip(ip: str) -> dict:
    if not ip:
        return {}
    try:
        ip = _validate_ipv4(ip)
    except ValueError:
        return {"error": f"invalid ip: {ip}"}

    relays = db.get_active_relays()
    results = {}

    async def _process(relay):
        ok, data = await _agent_request(relay, "POST", "/whitelist/remove", {"ip": ip})
        db.mark_relay_synced(relay["id"], ok)
        results[relay["name"]] = {"ok": ok, **data}

    await asyncio.gather(*[_process(r) for r in relays], return_exceptions=True)
    return results


async def full_sync(relay_id: int | None = None) -> dict:
    """
    Отправляет whitelist на relay-агенты. Агент принимает данные и обрабатывает
    их в фоне (fire-and-forget), чтобы не упираться в Vercel timeout.
    Реальный результат проверяется через /health → last_sync.
    """
    clients = db.list_clients(include_blocked=False)

    banned_ips = {ban["ip"] for ban in db.list_ip_bans()}

    client_entries = []
    skipped_banned = 0
    for c in clients:
        ip = c.get("current_ip")
        if ip:
            try:
                ip = _validate_ipv4(ip)
                if ip in banned_ips:
                    skipped_banned += 1
                    logger.info("Sync skip: client #%d IP %s is blacklisted", c["id"], ip)
                    continue
                client_entries.append({"ip": ip, "client_id": c["id"]})
            except ValueError:
                logger.warning("Skipping non-IPv4: %s", ip)

    if relay_id:
        relays = [r for r in db.list_relays() if r["id"] == relay_id]
    else:
        relays = db.get_active_relays()

    if not relays:
        return {"error": "no_relays"}

    results = {}

    async def _sync(relay):
        ok, data = await _agent_request(
            relay, "POST", "/whitelist/sync",
            {"clients": client_entries},
            timeout=SYNC_TIMEOUT,
        )
        # Пометка synced=True если агент принял payload.
        # Фактический результат (успешно ли закомиттился ipset) придёт через /health.
        db.mark_relay_synced(relay["id"], ok)
        results[relay["name"]] = {
            "ok": ok,
            "accepted": data.get("accepted", False) if ok else False,
            "received": data.get("received", 0) if ok else 0,
            "skipped_banned": skipped_banned,
            **data,
        }

    await asyncio.gather(*[_sync(r) for r in relays], return_exceptions=True)
    return {
        "total_clients": len(client_entries),
        "skipped_banned": skipped_banned,
        "relays": results,
    }


# ═══════════════════════════════════════
# HEALTH & STATS & TRAFFIC
# ═══════════════════════════════════════

async def check_relay(relay: dict) -> dict:
    ok, data = await _agent_request(relay, "GET", "/health")
    if ok:
        db.update_relay_health(relay["id"], data)
    return {"ok": ok, **data}


async def get_relay_stats(relay: dict) -> dict:
    ok, data = await _agent_request(relay, "GET", "/stats")
    return {"ok": ok, **data}


async def get_relay_traffic(
    relay: dict,
    client_ip: str | None = None,
    summary: bool = False,
    top: int | None = None,
) -> dict:
    """
    summary=True → вернуть только totals без ips dict
    top=N → вернуть только N топ-IP по total_bytes
    """
    path = f"/traffic/{client_ip}" if client_ip else "/traffic"
    ok, data = await _agent_request(relay, "GET", path)
    
    if not ok or client_ip:
        return {"ok": ok, "relay": relay["name"], **data}

    # Серверная фильтрация (на стороне API, т.к. агент пока не принимает params)
    if summary:
        data.pop("ips", None)
    elif top is not None and "ips" in data:
        sorted_ips = sorted(
            data["ips"].items(),
            key=lambda x: x[1].get("total_bytes", 0),
            reverse=True
        )[:top]
        data["ips"] = dict(sorted_ips)
        data["truncated"] = True
        data["top_n"] = top

    return {"ok": ok, "relay": relay["name"], **data}


async def get_traffic_all_relays(client_ip: str | None = None) -> dict:
    relays = db.get_active_relays()
    results = {}

    async def _fetch(relay):
        result = await get_relay_traffic(relay, client_ip)
        results[relay["name"]] = result

    await asyncio.gather(*[_fetch(r) for r in relays], return_exceptions=True)
    return results


async def health_check_all() -> dict:
    relays = db.get_active_relays()
    results = {}

    async def _check(relay):
        result = await check_relay(relay)
        results[relay["name"]] = result

    await asyncio.gather(*[_check(r) for r in relays], return_exceptions=True)
    return results


# ═══════════════════════════════════════
# UPDATE
# ═══════════════════════════════════════

async def update_relay(relay: dict) -> dict:
    ok, data = await _agent_request(relay, "POST", "/update")
    return {"relay": relay["name"], **data}


async def update_all_relays() -> dict:
    relays = db.get_active_relays()
    if not relays:
        return {"error": "no_active_relays"}

    results = {}

    async def _update(relay):
        result = await update_relay(relay)
        results[relay["name"]] = result

    await asyncio.gather(*[_update(r) for r in relays], return_exceptions=True)
    return results


# ═══════════════════════════════════════
# RATE LIMITS
# ═══════════════════════════════════════

async def set_rate_limit(ip: str, mbps: float,
                         expires_at: str | None = None,
                         client_id: int | None = None) -> dict:
    """Применить rate-limit на ВСЕХ активных relay'ях."""
    try:
        ip = _validate_ipv4(ip)
    except ValueError as e:
        return {"error": str(e)}

    relays = db.get_active_relays()
    if not relays:
        return {"error": "no_active_relays"}

    results = {}
    payload = {"ip": ip, "mbps": float(mbps)}
    if expires_at:
        payload["expires_at"] = expires_at
    if client_id is not None:
        payload["client_id"] = client_id

    async def _process(relay):
        ok, data = await _agent_request(relay, "POST", "/rate-limit", payload)
        results[relay["name"]] = {"ok": ok, **data}

    await asyncio.gather(*[_process(r) for r in relays], return_exceptions=True)
    return results


async def remove_rate_limit(ip: str) -> dict:
    """Снять rate-limit на всех relay'ях."""
    try:
        ip = _validate_ipv4(ip)
    except ValueError as e:
        return {"error": str(e)}

    relays = db.get_active_relays()
    results = {}

    async def _process(relay):
        ok, data = await _agent_request(relay, "DELETE", f"/rate-limit/{ip}")
        results[relay["name"]] = {"ok": ok, **data}

    await asyncio.gather(*[_process(r) for r in relays], return_exceptions=True)
    return results


async def list_rate_limits_on_relay(relay: dict) -> dict:
    """Получить текущий список rate-limit'ов с конкретного relay'я."""
    ok, data = await _agent_request(relay, "GET", "/rate-limits")
    return {"ok": ok, **data}