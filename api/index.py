"""
Публичные:
  GET  /activate/{token}         — активация клиента

Защищённые (X-API-Key):
  POST/GET/DELETE  /api/clients
  POST/GET/DELETE  /api/relays
  POST/GET/DELETE  /api/blacklist
  POST             /api/relays/sync-all
  POST             /api/relays/update-all
  GET              /api/traffic
  GET              /api/stats
"""

import asyncio
import ipaddress
import logging
import os
import re

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .database import (
    create_client_record, get_client_by_token, get_client_by_id,
    list_clients, activate_client, block_client, delete_client,
    get_activation_logs, get_all_active_ips,
    count_clients_on_ip,
    add_relay, list_relays, get_active_relays, delete_relay, toggle_relay,
    add_ip_ban, remove_ip_ban, remove_ip_ban_by_ip, list_ip_bans,
    is_ip_banned, get_ip_ban,
)
from . import relay_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("panel")

API_VERSION = "1.2.1"
app = FastAPI(title="WARP Relay Panel", version=API_VERSION)


# ═══════════════════════════════════════
# AUTH
# ═══════════════════════════════════════

def require_api_key(x_api_key: str = Header(...)):
    if x_api_key != os.environ.get("API_KEY", ""):
        raise HTTPException(403, "Invalid API key")


# ═══════════════════════════════════════
# BOT DETECTION
# ═══════════════════════════════════════

_BOT_PATTERNS = re.compile(
    r"(TelegramBot|TwitterBot|Twitterbot|facebookexternalhit|"
    r"Facebot|WhatsApp|Slackbot|slack-imgproxy|LinkedInBot|"
    r"Discordbot|Googlebot|bingbot|YandexBot|Mail\.RU_Bot|"
    r"PetalBot|Applebot|Bytespider|GPTBot|CCBot|"
    r"bot|crawl|spider|preview|embed)",
    re.IGNORECASE,
)


def _is_bot(user_agent: str) -> bool:
    if not user_agent:
        return True
    return bool(_BOT_PATTERNS.search(user_agent))


# ═══════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════

class ClientCreate(BaseModel):
    label: str = ""
    note: str = ""

class ClientBlock(BaseModel):
    blocked: bool = True

class RelayCreate(BaseModel):
    name: str
    host: str
    agent_port: int = 7580
    agent_secret: str = ""

class RelayToggle(BaseModel):
    active: bool

class IPBanCreate(BaseModel):
    ip: str
    reason: str = ""

class IPBanRemove(BaseModel):
    ip: str


# ═══════════════════════════════════════
# HTML ШАБЛОНЫ
# ═══════════════════════════════════════

_BASE_STYLE = """
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       display:flex; justify-content:center; align-items:center;
       min-height:100vh; margin:0; background:#0f172a; color:#e2e8f0; }
.card { background:#1e293b; border-radius:16px; padding:2.5rem;
        max-width:420px; width:90%; text-align:center;
        box-shadow:0 4px 24px rgba(0,0,0,0.4); }
.icon { font-size:3rem; margin-bottom:0.75rem; }
h2 { margin-bottom:0.5rem; }
.ip { background:#334155; padding:0.5rem 1rem; border-radius:8px;
      font-family:'SF Mono',Monaco,monospace; margin:1rem 0; display:inline-block;
      font-size:1.1rem; letter-spacing:0.5px; }
.hint { color:#94a3b8; font-size:0.85rem; margin-top:1rem; line-height:1.5; }
.reason { background:#7f1d1d33; border:1px solid #7f1d1d; border-radius:8px;
          padding:0.75rem; margin-top:1rem; color:#fca5a5; font-size:0.9rem; }
"""

TMPL_SUCCESS = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WARP Relay — Активировано</title>
<style>{style} .icon {{ color:#4ade80; }}</style></head>
<body><div class="card">
  <div class="icon">✓</div>
  <h2>Доступ активирован</h2>
  <p>Ваш IP:</p>
  <div class="ip">{ip}</div>
  <p class="hint">Теперь подключайтесь к VPN.<br>При смене сети — активируйте повторно.</p>
</div></body></html>"""

TMPL_SAME = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WARP Relay — Активен</title>
<style>{style} .icon {{ color:#60a5fa; }}</style></head>
<body><div class="card">
  <div class="icon">✓</div>
  <h2>Доступ уже активен</h2>
  <div class="ip">{ip}</div>
  <p class="hint">Ваш IP не изменился, всё работает.</p>
</div></body></html>"""

TMPL_ERROR = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WARP Relay — Ошибка</title>
<style>{style} .icon {{ color:#f87171; }}</style></head>
<body><div class="card">
  <div class="icon">✕</div>
  <h2>{title}</h2>
  <p>{message}</p>
  <p class="hint">Обратитесь к администратору.</p>
</div></body></html>"""

TMPL_IP_BANNED = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WARP Relay — Заблокирован</title>
<style>{style} .icon {{ color:#f87171; }}</style></head>
<body><div class="card">
  <div class="icon">⛔</div>
  <h2>Доступ запрещён</h2>
  <p>Ваш IP-адрес заблокирован за нарушение правил.</p>
  {reason_block}
  <p class="hint">Если считаете это ошибкой — обратитесь к администратору.</p>
</div></body></html>"""

TMPL_BOT = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta property="og:title" content="WARP Relay — Активация">
<meta property="og:description" content="Нажмите на ссылку для активации доступа к VPN">
<meta property="og:type" content="website">
<title>WARP Relay</title></head>
<body></body></html>"""

ERROR_MAP = {
    "invalid_token": ("Неверная ссылка", "Ссылка активации недействительна."),
    "blocked": ("Доступ заблокирован", "Ваш аккаунт заблокирован."),
    "daily_limit": ("Лимит исчерпан", "Превышен лимит активаций на сегодня."),
    "ipv6_detected": ("IPv6 не поддерживается",
                      "Relay работает только с IPv4.<br>Отключите IPv6 или используйте мобильную сеть."),
    "invalid_ip": ("Ошибка определения IP", "Не удалось определить ваш IPv4 адрес."),
}


def _error_html(key: str, status: int = 403) -> HTMLResponse:
    title, message = ERROR_MAP.get(key, ("Ошибка", key))
    return HTMLResponse(
        TMPL_ERROR.format(style=_BASE_STYLE, title=title, message=message),
        status_code=status,
    )


def _ip_banned_html(reason: str = "") -> HTMLResponse:
    reason_block = ""
    if reason:
        reason_block = f'<div class="reason">Причина: {reason}</div>'
    return HTMLResponse(
        TMPL_IP_BANNED.format(style=_BASE_STYLE, reason_block=reason_block),
        status_code=403,
    )


# ═══════════════════════════════════════
# АКТИВАЦИЯ (публичный)
# ═══════════════════════════════════════

@app.get("/activate/{token}")
async def activate(token: str, request: Request):
    user_agent = request.headers.get("User-Agent", "")

    if _is_bot(user_agent):
        logger.info("Bot blocked: token=%s...%s ua=%s", token[:6], token[-4:], user_agent[:80])
        return HTMLResponse(TMPL_BOT, status_code=200)

    client_ip = (
        request.headers.get("X-Real-IP")
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

    logger.info("Activate: token=%s...%s ip=%s", token[:6], token[-4:], client_ip)

    result = activate_client(token, client_ip, user_agent)

    if "error" in result:
        if result["error"] == "ip_banned":
            logger.warning("IP banned: %s reason=%s", client_ip, result.get("reason", ""))
            return _ip_banned_html(result.get("reason", ""))
        return _error_html(result["error"])

    if result["status"] == "already_active":
        # Re-push IP на relay (идемпотентно).
        # Покрывает кейс: IP был удалён с relay после бана/разбана,
        # но в базе по-прежнему числится как текущий.
        await relay_client.add_ip(client_ip, client_id=result["client_id"])
        return HTMLResponse(TMPL_SAME.format(style=_BASE_STYLE, ip=client_ip))

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

    return HTMLResponse(TMPL_SUCCESS.format(style=_BASE_STYLE, ip=client_ip))


# ═══════════════════════════════════════
# API: КЛИЕНТЫ
# ═══════════════════════════════════════

@app.post("/api/clients", dependencies=[Depends(require_api_key)])
async def api_create_client(data: ClientCreate):
    return create_client_record(label=data.label, note=data.note)

@app.get("/api/clients", dependencies=[Depends(require_api_key)])
async def api_list_clients(include_blocked: bool = True):
    clients = list_clients(include_blocked=include_blocked)
    for c in clients:
        c.pop("_activations_today", None)
        c.pop("_reset_date", None)
        c.pop("_raw_current_ip_enc", None)
    return clients

@app.get("/api/clients/{client_id}", dependencies=[Depends(require_api_key)])
async def api_get_client(client_id: int):
    client = get_client_by_id(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    for key in ("_activations_today", "_reset_date", "_raw_current_ip_enc"):
        client.pop(key, None)
    return client

@app.get("/api/clients/{client_id}/logs", dependencies=[Depends(require_api_key)])
async def api_client_logs(client_id: int, limit: int = 50):
    client = get_client_by_id(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    logs = get_activation_logs(client_id, limit)
    return {"client_id": client_id, "label": client["label"], "logs": logs}

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

@app.patch("/api/clients/{client_id}/block", dependencies=[Depends(require_api_key)])
async def api_block_client(client_id: int, data: ClientBlock):
    client = get_client_by_id(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    block_client(client_id, data.blocked)
    if data.blocked and client["current_ip"]:
        others = count_clients_on_ip(client["current_ip"], exclude_client_id=client_id)
        if others == 0:
            await relay_client.remove_ip(client["current_ip"])
        else:
            logger.info("Block client #%d: IP %s shared by %d others, keeping",
                        client_id, client["current_ip"], others)
    return {"id": client_id, "is_blocked": data.blocked}

@app.delete("/api/clients/{client_id}", dependencies=[Depends(require_api_key)])
async def api_delete_client(client_id: int):
    client = delete_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    if client["current_ip"]:
        others = count_clients_on_ip(client["current_ip"])
        if others == 0:
            await relay_client.remove_ip(client["current_ip"])
        else:
            logger.info("Delete client #%d: IP %s shared by %d others, keeping",
                        client_id, client["current_ip"], others)
    return {"deleted": True, "id": client_id}


# ═══════════════════════════════════════
# API: IP BLACKLIST
# ═══════════════════════════════════════

@app.post("/api/blacklist", dependencies=[Depends(require_api_key)])
async def api_add_ip_ban(data: IPBanCreate):
    result = add_ip_ban(data.ip, data.reason)
    if not result.get("already_exists"):
        await relay_client.remove_ip(data.ip)
        logger.info("IP banned: %s reason=%s", data.ip, data.reason)
    return result

@app.get("/api/blacklist", dependencies=[Depends(require_api_key)])
async def api_list_ip_bans():
    return list_ip_bans()

@app.delete("/api/blacklist/{ban_id}", dependencies=[Depends(require_api_key)])
async def api_remove_ip_ban(ban_id: int):
    ok = remove_ip_ban(ban_id)
    if not ok:
        raise HTTPException(404, "Ban not found")
    return {"deleted": True, "id": ban_id}

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


# ═══════════════════════════════════════
# API: RELAY-СЕРВЕРЫ
# ═══════════════════════════════════════

@app.post("/api/relays", dependencies=[Depends(require_api_key)])
async def api_add_relay(data: RelayCreate):
    return add_relay(
        name=data.name, host=data.host,
        agent_port=data.agent_port, agent_secret=data.agent_secret,
    )

@app.get("/api/relays", dependencies=[Depends(require_api_key)])
async def api_list_relays():
    return list_relays()

@app.delete("/api/relays/{relay_id}", dependencies=[Depends(require_api_key)])
async def api_delete_relay(relay_id: int):
    ok = delete_relay(relay_id)
    if not ok:
        raise HTTPException(404, "Relay not found")
    return {"deleted": True, "id": relay_id}

@app.patch("/api/relays/{relay_id}/toggle", dependencies=[Depends(require_api_key)])
async def api_toggle_relay(relay_id: int, data: RelayToggle):
    toggle_relay(relay_id, data.active)
    return {"id": relay_id, "is_active": data.active}

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
async def api_relay_traffic(relay_id: int):
    relays = list_relays()
    relay = next((r for r in relays if r["id"] == relay_id), None)
    if not relay:
        raise HTTPException(404, "Relay not found")
    return await relay_client.get_relay_traffic(relay)

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


# ═══════════════════════════════════════
# API: ТРАФИК
# ═══════════════════════════════════════

@app.get("/api/traffic", dependencies=[Depends(require_api_key)])
async def api_traffic_all():
    return await relay_client.get_traffic_all_relays()


# ═══════════════════════════════════════
# API: СТАТИСТИКА
# ═══════════════════════════════════════

@app.get("/api/stats", dependencies=[Depends(require_api_key)])
async def api_stats():
    clients = list_clients()
    relays = list_relays()
    bans = list_ip_bans()
    return {
        "total_clients": len(clients),
        "active_clients": len([c for c in clients if c["current_ip"] and not c["is_blocked"]]),
        "blocked_clients": len([c for c in clients if c["is_blocked"]]),
        "total_relays": len(relays),
        "active_relays": len([r for r in relays if r["is_active"]]),
        "ip_bans": len(bans),
    }


# ═══════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "version": API_VERSION}