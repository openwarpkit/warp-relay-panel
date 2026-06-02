"""
Public:
  GET  /activate/{token}         - activate client

Protected (X-API-Key):
  POST/GET/DELETE  /api/clients
  POST             /api/clients/{id}/activate  - manual activation by IP
  POST/GET/DELETE  /api/relays
  POST/GET/DELETE  /api/blacklist
  POST             /api/relays/sync-all
  POST             /api/relays/update-all
  GET              /api/traffic
  GET              /api/stats
"""

import ipaddress
import logging
import os
import pathlib
import re
import string
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .database import (
    create_client_record, get_client_by_token, get_client_by_id,
    list_clients, activate_client, activate_client_by_id,
    block_client, delete_client, get_client_full,
    get_activation_logs, delete_activation_logs, get_all_active_ips,
    get_client_labels,
    add_relay, list_relays, get_active_relays, delete_relay, toggle_relay,
    add_ip_ban, remove_ip_ban, remove_ip_ban_by_ip, list_ip_bans,
    get_ip_ban,
    add_rate_limit, remove_rate_limit_by_ip, get_rate_limit,
    list_rate_limits, list_expired_rate_limits, get_sync_payload,
)
from . import relay_client
from .warp_networks import WARP_NETWORKS as _WARP_NETWORKS

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("panel")

API_VERSION = "1.3.0"
app = FastAPI(title="WARP Relay Panel", version=API_VERSION)



def require_api_key(x_api_key: str = Header(...)):
    expected_key = os.environ.get("API_KEY", "")
    if not expected_key or x_api_key != expected_key:
        raise HTTPException(403, "Invalid API key")



_BOT_PATTERNS = re.compile(
    r"(TelegramBot|TwitterBot|Twitterbot|facebookexternalhit|"
    r"Facebot|WhatsApp|Slackbot|slack-imgproxy|LinkedInBot|"
    r"Discordbot|Googlebot|bingbot|YandexBot|Mail\.RU_Bot|"
    r"PetalBot|Applebot|Bytespider|GPTBot|CCBot|"
    r"bot|crawl|spider|preview|embed|curl|node|Wget)",
    re.IGNORECASE,
)


def _is_bot(user_agent: str) -> bool:
    if not user_agent:
        return True
    return bool(_BOT_PATTERNS.search(user_agent))


def _is_warp_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _WARP_NETWORKS)



class ClientCreate(BaseModel):
    label: str = ""

class ClientBlock(BaseModel):
    blocked: bool = True

class ClientManualActivate(BaseModel):
    ip: str

class RelayCreate(BaseModel):
    name: str
    host: str
    agent_port: int = 7580
    agent_secret: str = ""
    agent_type: str = "full"

class RelayToggle(BaseModel):
    active: bool

class IPBanCreate(BaseModel):
    ip: str
    reason: str = ""

class IPBanRemove(BaseModel):
    ip: str

class RateLimitCreate(BaseModel):
    ip: str
    mbps: float
    expires_in_seconds: int | None = None   # None = forever
    reason: str = ""
    client_id: int | None = None

class RateLimitRemove(BaseModel):
    ip: str

class ClientLabelsRequest(BaseModel):
    ids: list[int]



_TPL_DIR = pathlib.Path(__file__).parent / "templates"


def _load(name: str) -> str:
    return (_TPL_DIR / name).read_text(encoding="utf-8")


_BASE_STYLE = _load("base.css")
_TPL_SUCCESS = string.Template(_load("success.html"))
_TPL_SAME = string.Template(_load("same.html"))
_TPL_ERROR = string.Template(_load("error.html"))
_TPL_IP_BANNED = string.Template(_load("ip_banned.html"))
_TPL_WARP_DETECTED = string.Template(_load("warp_detected.html"))
_TPL_BOT = _load("bot.html")
_TPL_LANDING = string.Template(_load("landing.html"))
_TPL_404 = string.Template(_load("404.html"))


ERROR_MAP = {
    "invalid_token": ("Invalid Link", "Activation link is invalid."),
    "blocked": ("Access Blocked", "Your account has been blocked."),
    "ipv6_detected": ("IPv6 not supported",
                      "Relay only supports IPv4. Disable IPv6 or use mobile network."),
    "invalid_ip": ("IP Detection Error", "Failed to determine your IPv4 address."),
}

# Human-readable errors for API responses (bot)
API_ERROR_MESSAGES = {
    "client_not_found": "Client not found",
    "blocked": "Your account is blocked",
    "ip_banned": "This IP address is banned",
    "invalid_ip": "Invalid IP address",
    "ipv6_not_supported": "IPv6 is not supported, IPv4 is required",
    "warp_detected": "Cloudflare WARP / VPN detected. Please disable WARP and try again",
}


def _error_html(key: str, status: int = 403) -> HTMLResponse:
    title, message = ERROR_MAP.get(key, ("Error", key))
    return HTMLResponse(
        _TPL_ERROR.safe_substitute(style=_BASE_STYLE, title=title, message=message),
        status_code=status,
    )


def _warp_detected_html(ip: str) -> HTMLResponse:
    return HTMLResponse(
        _TPL_WARP_DETECTED.safe_substitute(style=_BASE_STYLE, ip=ip),
        status_code=403,
    )


def _ip_banned_html(reason: str = "") -> HTMLResponse:
    reason_block = ""
    if reason:
        reason_block = (
            f'<div class="notice notice-error"><b>Reason:</b> {reason}</div>'
        )
    return HTMLResponse(
        _TPL_IP_BANNED.safe_substitute(style=_BASE_STYLE, reason_block=reason_block),
        status_code=403,
    )


def _rate_limit_block_html(rate_limit: dict | None) -> str:
    if not rate_limit:
        return ""
    mbps = rate_limit.get("mbps")
    expires_at = rate_limit.get("expires_at")
    if expires_at:
        until = f"until {expires_at[:16].replace('T', ' ')} UTC"
    else:
        until = "unlimited"
    return (
        '<div class="rate-limit">'
        '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/>'
        '<line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
        f'<span>Rate limit: <b>{mbps} Mbps</b> ({until})</span>'
        '</div>'
    )


# LANDING (public)

@app.get("/")
async def landing():
    return HTMLResponse(_TPL_LANDING.safe_substitute(style=_BASE_STYLE))


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api"):
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return HTMLResponse(_TPL_404.safe_substitute(style=_BASE_STYLE), status_code=404)


# ACTIVATION (public)

@app.get("/activate/{token}")
async def activate(token: str, request: Request):
    user_agent = request.headers.get("User-Agent", "")

    if _is_bot(user_agent):
        logger.info("Bot blocked: token=%s...%s ua=%s", token[:6], token[-4:], user_agent[:80])
        return HTMLResponse(_TPL_BOT, status_code=200)

    client_ip = (
        request.headers.get("x-relay-real-ip")
        or request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.client.host
    )

    try:
        addr = ipaddress.ip_address(client_ip)
        if isinstance(addr, ipaddress.IPv6Address):
            if addr.ipv4_mapped:
                client_ip = str(addr.ipv4_mapped)
            else:
                logger.warning("IPv6 rejected: %s", client_ip)
                return _error_html("ipv6_detected", 400)
    except ValueError:
        logger.error("Invalid IP: %s", client_ip)
        return _error_html("invalid_ip", 400)

    if _is_warp_ip(client_ip):
        logger.warning("WARP/Cloudflare IP blocked: token=%s...%s ip=%s",
                       token[:6], token[-4:], client_ip)
        return _warp_detected_html(client_ip)

    logger.info("Activate: token=%s...%s ip=%s", token[:6], token[-4:], client_ip)

    result = activate_client(token, client_ip)

    if "error" in result:
        if result["error"] == "ip_banned":
            logger.warning("IP banned: %s reason=%s", client_ip, result.get("reason", ""))
            return _ip_banned_html(result.get("reason", ""))
        return _error_html(result["error"])

    rl_block = _rate_limit_block_html(result.get("rate_limit"))

    if result["status"] == "already_active":
        # Re-push IP to relay (idempotent).
        await relay_client.add_ip(client_ip, client_id=result["client_id"])
        return HTMLResponse(_TPL_SAME.safe_substitute(
            style=_BASE_STYLE, ip=client_ip, rate_limit_block=rl_block,
        ))

    old_ip = result.get("old_ip")
    new_ip = result["new_ip"]
    cid = result["client_id"]

    if result.get("old_ip_shared"):
        logger.info("Client #%d: %s → %s (old IP shared, keeping)", cid, old_ip, new_ip)
        old_ip = None
    else:
        logger.info("Client #%d: %s → %s", cid, old_ip or "new", new_ip)

    relay_results = await relay_client.add_ip(new_ip, old_ip, client_id=cid)
    logger.info("Relay sync: %s", relay_results)

    return HTMLResponse(_TPL_SUCCESS.safe_substitute(
        style=_BASE_STYLE, ip=client_ip, rate_limit_block=rl_block,
    ))



@app.post("/api/clients", dependencies=[Depends(require_api_key)])
async def api_create_client(data: ClientCreate):
    return create_client_record(label=data.label)

@app.get("/api/clients", dependencies=[Depends(require_api_key)])
async def api_list_clients(include_blocked: bool = True):
    return list_clients(include_blocked=include_blocked)


@app.post("/api/clients/labels", dependencies=[Depends(require_api_key)])
async def api_client_labels(data: ClientLabelsRequest):
    """Batch-resolve client_id → label.

    Returns {"<id>": "<label>"}; missing IDs → null."""
    found = get_client_labels(data.ids)
    return {str(cid): found.get(cid) for cid in data.ids}


@app.get("/api/clients/search", dependencies=[Depends(require_api_key)])
async def api_search_clients(ip: str, include_log_history: bool = True):
    if not ip.strip():
        raise HTTPException(400, "ip required")

    from .database import search_clients_by_ip
    clients = search_clients_by_ip(ip.strip(), include_log_history=include_log_history)

    for c in clients:
        if c["current_ip"] == ip:
            c["match_source"] = "current"
        elif c["previous_ip"] == ip:
            c["match_source"] = "previous"
        else:
            c["match_source"] = "history"

    return clients


@app.get("/api/clients/{client_id}", dependencies=[Depends(require_api_key)])
async def api_get_client(client_id: int):
    client = get_client_by_id(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client

@app.get("/api/clients/{client_id}/logs", dependencies=[Depends(require_api_key)])
async def api_client_logs(client_id: int, limit: int = 50):
    client = get_client_by_id(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    logs = get_activation_logs(client_id, limit)
    return {"client_id": client_id, "label": client["label"], "logs": logs}

@app.delete("/api/clients/{client_id}/logs", dependencies=[Depends(require_api_key)])
async def api_delete_client_logs(client_id: int):
    client = get_client_by_id(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    deleted = delete_activation_logs(client_id)
    logger.info("Deleted %d activation logs for client #%d", deleted, client_id)
    return {"deleted": deleted, "client_id": client_id}

@app.get("/api/clients/{client_id}/traffic", dependencies=[Depends(require_api_key)])
async def api_client_traffic(client_id: int):
    client = get_client_by_id(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    if not client["current_ip"]:
        return {"client_id": client_id, "label": client["label"],
                "ip": None, "relays": {}, "note": "No active IP"}
    results = await relay_client.get_traffic_all_relays(client["current_ip"])
    return {"client_id": client_id, "label": client["label"],
            "ip": client["current_ip"], "relays": results}

@app.get("/api/clients/{client_id}/full", dependencies=[Depends(require_api_key)])
async def api_get_client_full(client_id: int):
    """Client + ban flags + current rate_limit. 1 RPC."""
    client = get_client_full(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client

@app.post("/api/clients/{client_id}/activate", dependencies=[Depends(require_api_key)])
async def api_activate_client_manual(client_id: int, data: ClientManualActivate):
    """Manual client activation by IP (bot called)."""
    ip = data.ip.strip()

    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            if addr.ipv4_mapped:
                ip = str(addr.ipv4_mapped)
            else:
                return {"error": "ipv6_not_supported",
                        "detail": API_ERROR_MESSAGES["ipv6_not_supported"]}
    except ValueError:
        return {"error": "invalid_ip",
                "detail": API_ERROR_MESSAGES["invalid_ip"]}

    if _is_warp_ip(ip):
        logger.warning("Manual activate blocked (WARP): client #%d ip=%s",
                       client_id, ip)
        return {"error": "warp_detected",
                "detail": API_ERROR_MESSAGES["warp_detected"]}

    result = activate_client_by_id(client_id, ip)

    if "error" in result:
        error_key = result["error"]
        detail = API_ERROR_MESSAGES.get(error_key, error_key)
        if error_key == "ip_banned" and result.get("reason"):
            detail += f": {result['reason']}"
        return {"error": error_key, "detail": detail}

    if result["status"] == "already_active":
        await relay_client.add_ip(ip, client_id=result["client_id"])
        logger.info("Manual activate (same IP): client #%d ip=%s", client_id, ip)
        return {
            "status": "already_active", "client_id": client_id, "ip": ip,
            "rate_limit": result.get("rate_limit"),
        }

    old_ip = result.get("old_ip")
    new_ip = result["new_ip"]

    if result.get("old_ip_shared"):
        logger.info("Manual activate: client #%d %s → %s (old IP shared, keeping)",
                     client_id, old_ip, new_ip)
        old_ip = None
    else:
        logger.info("Manual activate: client #%d %s → %s",
                     client_id, old_ip or "new", new_ip)

    relay_results = await relay_client.add_ip(new_ip, old_ip, client_id=client_id)
    logger.info("Manual activate relay sync: %s", relay_results)

    return {
        "status": "activated",
        "client_id": client_id,
        "ip": new_ip,
        "old_ip": result.get("old_ip"),
        "rate_limit": result.get("rate_limit"),
        "relay_sync": relay_results,
    }

@app.patch("/api/clients/{client_id}/block", dependencies=[Depends(require_api_key)])
async def api_block_client(client_id: int, data: ClientBlock):
    """Block/unblock via atomic RPC."""
    updated = block_client(client_id, data.blocked)
    if not updated:
        raise HTTPException(404, "Client not found")

    if data.blocked and updated["current_ip"] and not updated["current_ip_shared"]:
        await relay_client.remove_ip(updated["current_ip"])
    elif data.blocked and updated["current_ip"]:
        logger.info("Block client #%d: IP %s shared, keeping in ipset",
                    client_id, updated["current_ip"])
    return updated


@app.delete("/api/clients/{client_id}", dependencies=[Depends(require_api_key)])
async def api_delete_client(client_id: int):
    """Deletion via atomic RPC: returns {id, current_ip, current_ip_shared}."""
    result = delete_client(client_id)
    if not result:
        raise HTTPException(404, "Client not found")
    if result["current_ip"] and not result["current_ip_shared"]:
        await relay_client.remove_ip(result["current_ip"])
    elif result["current_ip"]:
        logger.info("Delete client #%d: IP %s shared, keeping in ipset",
                    client_id, result["current_ip"])
    return {"deleted": True, "id": client_id}



@app.post("/api/blacklist", dependencies=[Depends(require_api_key)])
async def api_add_ip_ban(data: IPBanCreate):
    result = add_ip_ban(data.ip, data.reason)
    if not result.get("already_exists"):
        await relay_client.remove_ip(data.ip)
        logger.info("IP banned: %s reason=%s", data.ip, data.reason)
    return result

@app.get("/api/blacklist", dependencies=[Depends(require_api_key)])
async def api_list_ip_bans(page: int | None = None, per_page: int = 20, search: str | None = None):
    if page is None:
        return list_ip_bans()
    from .database import list_ip_bans_paginated
    return list_ip_bans_paginated(page=page, per_page=per_page, search=search)


@app.delete("/api/blacklist/by-ip", dependencies=[Depends(require_api_key)])
async def api_remove_ip_ban_by_ip(data: IPBanRemove):
    ok = remove_ip_ban_by_ip(data.ip)
    if not ok:
        raise HTTPException(404, "IP not in blacklist")
    logger.info("IP unbanned: %s", data.ip)
    return {"deleted": True, "ip": data.ip}

@app.get("/api/blacklist/check/{ip}", dependencies=[Depends(require_api_key)])
async def api_check_ip_ban(ip: str):
    ban = get_ip_ban(ip)
    if ban:
        return {"banned": True, **ban}
    return {"banned": False, "ip": ip}


@app.get("/api/blacklist/{ban_id}", dependencies=[Depends(require_api_key)])
async def api_get_ip_ban(ban_id: int):
    from .database import get_ip_ban_by_id
    ban = get_ip_ban_by_id(ban_id)
    if not ban:
        raise HTTPException(404, "Ban not found")
    return ban

@app.delete("/api/blacklist/{ban_id}", dependencies=[Depends(require_api_key)])
async def api_remove_ip_ban(ban_id: int):
    ok = remove_ip_ban(ban_id)
    if not ok:
        raise HTTPException(404, "Ban not found")
    return {"deleted": True, "id": ban_id}



@app.post("/api/relays", dependencies=[Depends(require_api_key)])
async def api_add_relay(data: RelayCreate):
    return add_relay(
        name=data.name, host=data.host,
        agent_port=data.agent_port, agent_secret=data.agent_secret,
        agent_type=data.agent_type,
    )

@app.get("/api/relays", dependencies=[Depends(require_api_key)])
async def api_list_relays(fields: str = "full"):
    """fields=basic - without last_health (lighter payload)."""
    return list_relays(fields=fields)


@app.delete("/api/relays/{relay_id}", dependencies=[Depends(require_api_key)])
async def api_delete_relay(relay_id: int):
    ok = delete_relay(relay_id)
    if not ok:
        raise HTTPException(404, "Relay not found")
    return {"deleted": True, "id": relay_id}

@app.patch("/api/relays/{relay_id}/toggle", dependencies=[Depends(require_api_key)])
async def api_toggle_relay(relay_id: int, data: RelayToggle):
    relay = toggle_relay(relay_id, data.active)
    if not relay:
        raise HTTPException(404, "Relay not found")
    return relay

@app.get("/api/relays/{relay_id}/health", dependencies=[Depends(require_api_key)])
async def api_relay_health(relay_id: int):
    relays = list_relays()
    relay = next((r for r in relays if r["id"] == relay_id), None)
    if not relay:
        raise HTTPException(404, "Relay not found")
    return await relay_client.check_relay(relay)

@app.get("/api/relays/{relay_id}/stats", dependencies=[Depends(require_api_key)])
async def api_relay_stats(relay_id: int):
    relays = list_relays()
    relay = next((r for r in relays if r["id"] == relay_id), None)
    if not relay:
        raise HTTPException(404, "Relay not found")
    return await relay_client.get_relay_stats(relay)

@app.get("/api/relays/{relay_id}/traffic", dependencies=[Depends(require_api_key)])
async def api_relay_traffic(relay_id: int, summary: bool = False, top: int | None = None):
    relays = list_relays()
    relay = next((r for r in relays if r["id"] == relay_id), None)
    if not relay:
        raise HTTPException(404, "Relay not found")
    return await relay_client.get_relay_traffic(relay, summary=summary, top=top)

@app.post("/api/relays/{relay_id}/sync", dependencies=[Depends(require_api_key)])
async def api_sync_relay(relay_id: int):
    return await relay_client.full_sync(relay_id=relay_id)

@app.post("/api/relays/sync-all", dependencies=[Depends(require_api_key)])
async def api_sync_all():
    return await relay_client.full_sync()

@app.get("/api/relays/health-all", dependencies=[Depends(require_api_key)])
async def api_health_all():
    return await relay_client.health_check_all()

@app.post("/api/relays/{relay_id}/update", dependencies=[Depends(require_api_key)])
async def api_update_relay(relay_id: int):
    relays = list_relays()
    relay = next((r for r in relays if r["id"] == relay_id), None)
    if not relay:
        raise HTTPException(404, "Relay not found")
    return await relay_client.update_relay(relay)

@app.post("/api/relays/update-all", dependencies=[Depends(require_api_key)])
async def api_update_all_relays():
    return await relay_client.update_all_relays()



@app.get("/api/traffic", dependencies=[Depends(require_api_key)])
async def api_traffic_all():
    return await relay_client.get_traffic_all_relays()



@app.get("/api/stats", dependencies=[Depends(require_api_key)])
async def api_stats():
    """Lightweight statistics via dashboard_stats RPC."""
    from .database import get_dashboard_stats
    return get_dashboard_stats()


@app.get("/api/dashboard", dependencies=[Depends(require_api_key)])
async def api_dashboard():
    """Main dashboard screen: relays(basic) + stats."""
    from .database import get_dashboard_stats
    relays = list_relays(fields="basic")
    stats = get_dashboard_stats()

    stats["total_relays"] = len(relays)
    stats["active_relays"] = sum(1 for r in relays if r.get("is_active"))

    return {"relays": relays, "stats": stats}



@app.post("/api/rate-limits", dependencies=[Depends(require_api_key)])
async def api_set_rate_limit(data: RateLimitCreate):
    """
    Create/update rate-limit for an IP.
    expires_in_seconds=null means unlimited.
    Saves in Supabase and pushes to all active relays.
    """
    try:
        ip = str(ipaddress.ip_address(data.ip))
        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address):
            return {"error": "ipv6_not_supported"}
    except ValueError:
        return {"error": "invalid_ip"}
    if data.mbps <= 0:
        raise HTTPException(400, "mbps must be > 0")

    expires_at = None
    if data.expires_in_seconds is not None and data.expires_in_seconds > 0:
        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(seconds=data.expires_in_seconds)
        ).isoformat()

    record = add_rate_limit(
        ip=ip, mbps=data.mbps,
        expires_at=expires_at, reason=data.reason,
        client_id=data.client_id,
    )
    relay_results = await relay_client.set_rate_limit(
        ip=ip, mbps=data.mbps,
        expires_at=expires_at, client_id=data.client_id,
    )
    logger.info("Rate-limit set: %s = %s Mbps (expires=%s)", ip, data.mbps, expires_at)
    return {**record, "applied_to": relay_results}


@app.delete("/api/rate-limits/by-ip", dependencies=[Depends(require_api_key)])
async def api_remove_rate_limit_by_ip(data: RateLimitRemove):
    """Remove rate-limit by IP from DB and all relays."""
    deleted = remove_rate_limit_by_ip(data.ip)
    relay_results = await relay_client.remove_rate_limit(data.ip)
    if not deleted and not any(r.get("ok") for r in relay_results.values()):
        raise HTTPException(404, "Rate-limit not found")
    return {"deleted": True, "ip": data.ip, "removed_from": relay_results}


@app.delete("/api/rate-limits/{ip}", dependencies=[Depends(require_api_key)])
async def api_remove_rate_limit(ip: str):
    """Remove rate-limit by IP from URL."""
    deleted = remove_rate_limit_by_ip(ip)
    relay_results = await relay_client.remove_rate_limit(ip)
    if not deleted and not any(r.get("ok") for r in relay_results.values()):
        raise HTTPException(404, "Rate-limit not found")
    return {"deleted": True, "ip": ip, "removed_from": relay_results}


@app.get("/api/rate-limits", dependencies=[Depends(require_api_key)])
async def api_list_rate_limits():
    return list_rate_limits()


@app.get("/api/rate-limits/expired", dependencies=[Depends(require_api_key)])
async def api_list_expired_rate_limits():
    """For external scheduler: everything to remove (expires_at < NOW)."""
    return list_expired_rate_limits()


@app.get("/api/rate-limits/{ip}", dependencies=[Depends(require_api_key)])
async def api_get_rate_limit(ip: str):
    rl = get_rate_limit(ip)
    if not rl:
        return {"ip": ip, "limited": False}
    return {"limited": True, **rl}


# WHITELIST PAYLOAD (for startup-resync agent)

@app.get("/api/relays/{relay_id}/whitelist-payload",
         dependencies=[Depends(require_api_key)])
async def api_relay_whitelist_payload(relay_id: int):
    """
    Full payload for the agent: decrypted client IPs + current rate_limits.
    Called by agent on startup to rebuild in-memory state.
    """
    payload = get_sync_payload()
    logger.info("Whitelist-payload requested by relay #%d: %d clients, %d rate_limits",
                relay_id, len(payload["clients"]), len(payload["rate_limits"]))
    return payload



@app.get("/health")
async def health():
    return {"status": "ok", "version": API_VERSION}