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
UPDATE_TIMEOUT = 60.0  # обновление может занять время (git pull, pip)


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
    clients = db.list_clients(include_blocked=False)
    client_entries = []
    for c in clients:
        ip = c.get("current_ip")
        if ip:
            try:
                ip = _validate_ipv4(ip)
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
        )
        db.mark_relay_synced(relay["id"], ok)
        results[relay["name"]] = {
            "ok": ok, "ips_synced": len(client_entries) if ok else 0, **data,
        }

    await asyncio.gather(*[_sync(r) for r in relays], return_exceptions=True)
    return results


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


async def get_relay_traffic(relay: dict, client_ip: str | None = None) -> dict:
    path = f"/traffic/{client_ip}" if client_ip else "/traffic"
    ok, data = await _agent_request(relay, "GET", path)
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
    """Отправить команду самообновления на один relay."""
    ok, data = await _agent_request(
        relay, "POST", "/update", timeout=UPDATE_TIMEOUT,
    )
    return {"ok": ok, "relay": relay["name"], **data}


async def update_all_relays() -> dict:
    """Обновить все активные relay."""
    relays = db.get_active_relays()
    if not relays:
        return {"error": "no_active_relays"}

    results = {}

    async def _update(relay):
        result = await update_relay(relay)
        results[relay["name"]] = result

    await asyncio.gather(*[_update(r) for r in relays], return_exceptions=True)
    return results