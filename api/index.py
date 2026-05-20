"""
Публичные:
  GET  /activate/{token}         — активация клиента

Защищённые (X-API-Key):
  POST/GET/DELETE  /api/clients
  POST             /api/clients/{id}/activate  — ручная активация по IP
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
import re
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("panel")

API_VERSION = "1.3.0"
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
    r"bot|crawl|spider|preview|embed|curl|node|Wget)",
    re.IGNORECASE,
)


def _is_bot(user_agent: str) -> bool:
    if not user_agent:
        return True
    return bool(_BOT_PATTERNS.search(user_agent))


# ═══════════════════════════════════════
# WARP / CLOUDFLARE DETECTION
# ═══════════════════════════════════════

# Cloudflare published IPv4 ranges (включают WARP egress) + RFC 6598 CGNAT
# (используется WARP внутренне). Источник: https://www.cloudflare.com/ips-v4
_WARP_NETWORKS = [
    ipaddress.ip_network(cidr) for cidr in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        # CGNAT — внутренние egress-IP WARP
        "100.64.0.0/10",
    )
]


def _is_warp_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _WARP_NETWORKS)


# ═══════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════

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
    expires_in_seconds: int | None = None   # None = бессрочно
    reason: str = ""
    client_id: int | None = None

class RateLimitRemove(BaseModel):
    ip: str

class ClientLabelsRequest(BaseModel):
    ids: list[int]


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
.ratelimit { background:#78350f33; border:1px solid #b45309; border-radius:8px;
             padding:0.75rem; margin-top:1rem; color:#fcd34d; font-size:0.9rem; }
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
  {rate_limit_block}
  <p class="hint">Теперь подключайтесь к WARP.<br>При смене сети — активируйте повторно.</p>
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
  {rate_limit_block}
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

TMPL_WARP_DETECTED = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WARP Relay — Отключите VPN</title>
<style>{style} .icon {{ color:#fbbf24; }}
.btn {{ background:#3b82f6; color:#fff; border:none; border-radius:8px;
       padding:0.75rem 1.5rem; font-size:1rem; font-weight:600;
       cursor:pointer; margin-top:1.25rem; transition:background 0.15s; }}
.btn:hover {{ background:#2563eb; }}
.steps {{ text-align:left; margin:1rem 0; color:#cbd5e1; font-size:0.9rem;
         line-height:1.7; padding-left:1.25rem; }}
.steps li {{ margin-bottom:0.25rem; }}
</style></head>
<body><div class="card">
  <div class="icon">⚠</div>
  <h2>Обнаружен WARP / VPN</h2>
  <p>Активация невозможна: ваш IP принадлежит подсети Cloudflare&nbsp;WARP.</p>
  <div class="ip">{ip}</div>
  <ol class="steps">
    <li>Отключите Cloudflare&nbsp;WARP, 1.1.1.1 или любой&nbsp;VPN</li>
    <li>Убедитесь, что соединение идёт через домашний&nbsp;Wi-Fi или мобильную сеть</li>
    <li>Нажмите кнопку <b>Обновить</b></li>
  </ol>
  <button class="btn" onclick="location.reload()">Обновить</button>
  <p class="hint">После активации можно снова включить WARP, если нужно.</p>
</div></body></html>"""

TMPL_BOT = """<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<meta property="og:title" content="WARP Relay — Активация">
<meta property="og:description" content="Нажмите на ссылку для активации доступа к WARP">
<meta property="og:type" content="website">
<title>WARP Relay</title></head>
<body></body></html>"""

ERROR_MAP = {
    "invalid_token": ("Неверная ссылка", "Ссылка активации недействительна."),
    "blocked": ("Доступ заблокирован", "Ваш аккаунт заблокирован."),
    "ipv6_detected": ("IPv6 не поддерживается",
                      "Relay работает только с IPv4.<br>Отключите IPv6 или используйте мобильную сеть."),
    "invalid_ip": ("Ошибка определения IP", "Не удалось определить ваш IPv4 адрес."),
}

# Человекочитаемые ошибки для API-ответов (бот)
API_ERROR_MESSAGES = {
    "client_not_found": "Клиент не найден",
    "blocked": "Ваш аккаунт заблокирован",
    "ip_banned": "Этот IP-адрес заблокирован",
    "invalid_ip": "Некорректный IP-адрес",
    "ipv6_not_supported": "IPv6 не поддерживается, нужен IPv4",
    "warp_detected": "Обнаружен Cloudflare WARP / VPN. Отключите WARP и повторите активацию",
}


def _error_html(key: str, status: int = 403) -> HTMLResponse:
    title, message = ERROR_MAP.get(key, ("Ошибка", key))
    return HTMLResponse(
        TMPL_ERROR.format(style=_BASE_STYLE, title=title, message=message),
        status_code=status,
    )


def _warp_detected_html(ip: str) -> HTMLResponse:
    return HTMLResponse(
        TMPL_WARP_DETECTED.format(style=_BASE_STYLE, ip=ip),
        status_code=403,
    )


def _ip_banned_html(reason: str = "") -> HTMLResponse:
    reason_block = ""
    if reason:
        reason_block = f'<div class="reason">Причина: {reason}</div>'
    return HTMLResponse(
        TMPL_IP_BANNED.format(style=_BASE_STYLE, reason_block=reason_block),
        status_code=403,
    )


def _rate_limit_block_html(rate_limit: dict | None) -> str:
    if not rate_limit:
        return ""
    mbps = rate_limit.get("mbps")
    expires_at = rate_limit.get("expires_at")
    if expires_at:
        until = f"до {expires_at[:16].replace('T', ' ')} UTC"
    else:
        until = "бессрочно"
    return (
        f'<div class="ratelimit">⚠ Ограничение скорости: '
        f'<b>{mbps} Mbps</b> ({until})</div>'
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
        # Re-push IP на relay (идемпотентно).
        await relay_client.add_ip(client_ip, client_id=result["client_id"])
        return HTMLResponse(TMPL_SAME.format(
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

    return HTMLResponse(TMPL_SUCCESS.format(
        style=_BASE_STYLE, ip=client_ip, rate_limit_block=rl_block,
    ))


# ═══════════════════════════════════════
# API: КЛИЕНТЫ
# ═══════════════════════════════════════

@app.post("/api/clients", dependencies=[Depends(require_api_key)])
async def api_create_client(data: ClientCreate):
    return create_client_record(label=data.label)

@app.get("/api/clients", dependencies=[Depends(require_api_key)])
async def api_list_clients(include_blocked: bool = True):
    return list_clients(include_blocked=include_blocked)


@app.post("/api/clients/labels", dependencies=[Depends(require_api_key)])
async def api_client_labels(data: ClientLabelsRequest):
    """Batch-резолв client_id → label.

    Удобно, чтобы по `client_ids` из `/api/traffic` показать имена клиентов
    одним запросом вместо N штук `/api/clients/{id}`.

    Возвращает {"<id>": "<label>"}; отсутствующие ID → null."""
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
    """Клиент + флаги бана current/previous + текущий rate_limit. 1 RPC."""
    client = get_client_full(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client

@app.post("/api/clients/{client_id}/activate", dependencies=[Depends(require_api_key)])
async def api_activate_client_manual(client_id: int, data: ClientManualActivate):
    """Ручная активация клиента по IP (вызывается ботом)."""
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
    """Блокировка/разблокировка через атомарный RPC. current_ip_shared
    приходит сразу — не нужен отдельный count_clients_on_ip."""
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
    """Удаление через атомарный RPC: возвращает {id, current_ip, current_ip_shared}."""
    result = delete_client(client_id)
    if not result:
        raise HTTPException(404, "Client not found")
    if result["current_ip"] and not result["current_ip_shared"]:
        await relay_client.remove_ip(result["current_ip"])
    elif result["current_ip"]:
        logger.info("Delete client #%d: IP %s shared, keeping in ipset",
                    client_id, result["current_ip"])
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
async def api_list_relays(fields: str = "full"):
    """fields=basic — без last_health (легче payload)."""
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
    """Лёгкая статистика через RPC dashboard_stats."""
    from .database import get_dashboard_stats
    return get_dashboard_stats()


@app.get("/api/dashboard", dependencies=[Depends(require_api_key)])
async def api_dashboard():
    """Главный экран: relays(basic) + stats. Stats через RPC."""
    from .database import get_dashboard_stats
    relays = list_relays(fields="basic")
    stats = get_dashboard_stats()

    stats["total_relays"] = len(relays)
    stats["active_relays"] = sum(1 for r in relays if r.get("is_active"))

    return {"relays": relays, "stats": stats}


# ═══════════════════════════════════════
# API: RATE-LIMITS
# ═══════════════════════════════════════

@app.post("/api/rate-limits", dependencies=[Depends(require_api_key)])
async def api_set_rate_limit(data: RateLimitCreate):
    """
    Создать/обновить rate-limit для IP.
    expires_in_seconds=null означает бессрочно.
    Сохраняет в Supabase + push на все активные relay'и.
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
    """Снять rate-limit по IP. Удаляет из БД и со всех relay'ев."""
    deleted = remove_rate_limit_by_ip(data.ip)
    relay_results = await relay_client.remove_rate_limit(data.ip)
    if not deleted and not any(r.get("ok") for r in relay_results.values()):
        raise HTTPException(404, "Rate-limit not found")
    return {"deleted": True, "ip": data.ip, "removed_from": relay_results}


@app.delete("/api/rate-limits/{ip}", dependencies=[Depends(require_api_key)])
async def api_remove_rate_limit(ip: str):
    """Снять rate-limit по IP в URL."""
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
    """Для внешнего шедулера юзера: всё, что пора снять (expires_at < NOW)."""
    return list_expired_rate_limits()


@app.get("/api/rate-limits/{ip}", dependencies=[Depends(require_api_key)])
async def api_get_rate_limit(ip: str):
    rl = get_rate_limit(ip)
    if not rl:
        return {"ip": ip, "limited": False}
    return {"limited": True, **rl}


# ═══════════════════════════════════════
# WHITELIST PAYLOAD (для startup-resync агента)
# ═══════════════════════════════════════

@app.get("/api/relays/{relay_id}/whitelist-payload",
         dependencies=[Depends(require_api_key)])
async def api_relay_whitelist_payload(relay_id: int):
    """
    Полный payload для агента: расшифрованные IP клиентов + текущие rate_limits.
    Вызывается агентом на startup для пересборки in-memory state.
    relay_id передаётся для логирования; payload одинаков для всех relay'ев.
    """
    payload = get_sync_payload()
    logger.info("Whitelist-payload requested by relay #%d: %d clients, %d rate_limits",
                relay_id, len(payload["clients"]), len(payload["rate_limits"]))
    return payload


# ═══════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "version": API_VERSION}