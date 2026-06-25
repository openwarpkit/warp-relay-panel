"""
HTTP client for relay agents.
"""

import asyncio
import ipaddress
import logging
import socket
import httpx
from . import database as db

logger = logging.getLogger("relay_client")

AGENT_TIMEOUT = 10.0
SYNC_TIMEOUT = 30.0  # For /whitelist/sync (large payload)

_LIMITS = httpx.Limits(
    max_keepalive_connections=20,
    max_connections=100,
    keepalive_expiry=30.0,
)
_TIMEOUT = httpx.Timeout(AGENT_TIMEOUT, connect=5.0, pool=5.0)
_RECYCLE_AFTER = 8

_http_client: httpx.AsyncClient | None = None
_client_lock = asyncio.Lock()
_consecutive_timeouts = 0


def _new_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(limits=_LIMITS, timeout=_TIMEOUT)


async def _get_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        async with _client_lock:
            if _http_client is None or _http_client.is_closed:
                _http_client = _new_client()
    return _http_client


async def _recycle_client(stale: httpx.AsyncClient | None) -> None:
    global _http_client, _consecutive_timeouts
    async with _client_lock:
        if _http_client is not stale:
            return
        old, _http_client = _http_client, _new_client()
        _consecutive_timeouts = 0
    if old is not None:
        try:
            await old.aclose()
        except Exception:
            pass
    logger.warning("recycled httpx client (outbound pool wedged)")


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


def _resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return socket.gethostbyname(host)


async def _agent_request(relay: dict, method: str, path: str,
                         json_data: dict = None,
                         timeout: float = AGENT_TIMEOUT) -> tuple[bool, dict]:
    global _consecutive_timeouts
    host = relay['host']
    try:
        resolved_ip = await asyncio.to_thread(_resolve_host, host)
        ip_obj = ipaddress.ip_address(resolved_ip)
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
            msg = f"[{relay['name']}] SSRF blocked: {host} resolved to local IP {resolved_ip}"
            logger.error(msg)
            return False, {"error": msg}
    except socket.gaierror:
        msg = f"[{relay['name']}] DNS error: could not resolve {host}"
        logger.error(msg)
        return False, {"error": msg}

    # Prevent DNS rebinding by connecting to the resolved IP directly
    url = f"http://{resolved_ip}:{relay['agent_port']}{path}"
    headers = _agent_headers(relay)
    headers["Host"] = host

    client = await _get_client()
    try:
        resp = await client.request(
            method, url,
            headers=headers,
            json=json_data,
            timeout=timeout,
        )
        data = resp.json()
        _consecutive_timeouts = 0
        if resp.status_code >= 400:
            logger.warning("[%s] %s %s → %d: %s",
                           relay["name"], method, path, resp.status_code, data)
            return False, data
        return True, data
    except httpx.PoolTimeout:
        msg = f"[{relay['name']}] timeout: {method} {path}"
        logger.error("%s (pool exhausted)", msg)
        await _recycle_client(client)
        return False, {"error": msg}
    except httpx.TimeoutException:
        msg = f"[{relay['name']}] timeout: {method} {path}"
        logger.error(msg)
        _consecutive_timeouts += 1
        if _consecutive_timeouts >= _RECYCLE_AFTER:
            await _recycle_client(client)
        return False, {"error": msg}
    except Exception as e:
        msg = f"[{relay['name']}] error: {e}"
        logger.error(msg)
        return False, {"error": msg}



async def add_ip(new_ip: str, old_ip: str | None = None,
                 client_id: int | None = None) -> dict:
    try:
        new_ip = _validate_ipv4(new_ip)
        if old_ip:
            old_ip = _validate_ipv4(old_ip)
    except ValueError as e:
        logger.error("IP validation: %s", e)
        return {"error": str(e)}

    relays = db.get_active_relays(agent_type="full")
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

    relays = db.get_active_relays(agent_type="full")
    results = {}

    async def _process(relay):
        ok, data = await _agent_request(relay, "POST", "/whitelist/remove", {"ip": ip})
        db.mark_relay_synced(relay["id"], ok)
        results[relay["name"]] = {"ok": ok, **data}

    await asyncio.gather(*[_process(r) for r in relays], return_exceptions=True)
    return results


async def full_sync(relay_id: int | None = None) -> dict:
    """Sync whitelist + rate-limits to full relays; payload from get_sync_payload RPC."""
    payload = db.get_sync_payload()
    client_entries = payload["clients"]
    rate_limit_entries = payload["rate_limits"]
    skipped_banned = 0

    if relay_id:
        relays = [r for r in db.list_relays() if r["id"] == relay_id and r.get("agent_type", "full") == "full"]
    else:
        relays = db.get_active_relays(agent_type="full")

    if not relays:
        return {"error": "no_relays"}

    results = {}

    async def _sync(relay):
        ok, data = await _agent_request(
            relay, "POST", "/whitelist/sync",
            {
                "clients": client_entries,
                "rate_limits": rate_limit_entries,
            },
            timeout=SYNC_TIMEOUT,
        )
        # Agent processes payload synchronously now.
        # Actual results are directly in data: synced, clients, invalid, rate_limits_applied
        db.mark_relay_synced(relay["id"], ok and data.get("ok", False))
        results[relay["name"]] = {
            "ok": ok and data.get("ok", False),
            "synced": data.get("synced", 0) if ok else 0,
            "rate_limits_applied": data.get("rate_limits_applied", 0) if ok else 0,
            "skipped_banned": skipped_banned,
            **data,
        }

    await asyncio.gather(*[_sync(r) for r in relays], return_exceptions=True)
    return {
        "total_clients": len(client_entries),
        "total_rate_limits": len(rate_limit_entries),
        "skipped_banned": skipped_banned,
        "relays": results,
    }



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
    summary=True -> return only totals without ips dict
    top=N -> return only N top-IP by total_bytes

    Min-relays do not keep per-IP traffic (global shaping) - return empty
    without hitting the agent.
    """
    if relay.get("agent_type", "full") == "min":
        return {
            "ok": True, "relay": relay["name"], "agent_type": "min", "skipped": "min",
            "ips": {}, "ip_count": 0,
            "total_bytes": 0, "total_tx_bytes": 0, "total_rx_bytes": 0,
            "total": "0 B", "total_tx": "0 B", "total_rx": "0 B",
        }

    path = f"/traffic/{client_ip}" if client_ip else "/traffic"
    ok, data = await _agent_request(relay, "GET", path)
    
    if not ok or client_ip:
        return {"ok": ok, "relay": relay["name"], **data}

    # Server-side filtering (API side, since agent does not accept params yet)
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



async def set_rate_limit(ip: str, mbps: float,
                         expires_at: str | None = None,
                         client_id: int | None = None) -> dict:
    """Apply rate-limit to ALL active full-relays.
    Min-relays are ignored - they have a global limit, not per-IP."""
    try:
        ip = _validate_ipv4(ip)
    except ValueError as e:
        return {"error": str(e)}

    relays = db.get_active_relays(agent_type="full")
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
    """Remove rate-limit on all full-relays."""
    try:
        ip = _validate_ipv4(ip)
    except ValueError as e:
        return {"error": str(e)}

    relays = db.get_active_relays(agent_type="full")
    results = {}

    async def _process(relay):
        ok, data = await _agent_request(relay, "DELETE", f"/rate-limit/{ip}")
        results[relay["name"]] = {"ok": ok, **data}

    await asyncio.gather(*[_process(r) for r in relays], return_exceptions=True)
    return results


async def list_rate_limits_on_relay(relay: dict) -> dict:
    """Get current list of rate-limits from a specific relay."""
    ok, data = await _agent_request(relay, "GET", "/rate-limits")
    return {"ok": ok, **data}