"""
WARP Relay Panel — Vercel Serverless API

Публичные:
  GET  /activate/{token}         — активация клиента

Защищённые (X-API-Key):
  POST/GET/DELETE  /api/clients
  POST/GET/DELETE  /api/relays
  POST             /api/relays/sync-all
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
    add_relay, list_relays, get_active_relays, delete_relay, toggle_relay,
)
from . import relay_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("panel")

app = FastAPI(title="WARP Relay Panel", version="2.0.0")


# ═══════════════════════════════════════
# AUTH
# ═══════════════════════════════════════

def require_api_key(x_api_key: str = Header(...)):
    if x_api_key != os.environ.get("API_KEY", ""):
        raise HTTPException(403, "Invalid API key")


# ═══════════════════════════════════════
# BOT DETECTION
# ═══════════════════════════════════════

# Паттерны User-Agent известных ботов/краулеров, которые
# делают запросы для генерации превью ссылок (Telegram, WhatsApp,
# Discord, Twitter/X, Slack, Facebook и т.д.)
_BOT_PATTERNS = re.compile(
    r"(TelegramBot|TwitterBot|Twitterbot|facebookexternalhit|"
    r"Facebot|WhatsApp|Slackbot|slack-imgproxy|LinkedInBot|"
    r"Discordbot|Googlebot|bingbot|YandexBot|Mail\.RU_Bot|"
    r"PetalBot|Applebot|Bytespider|GPTBot|CCBot|"
    r"bot|crawl|spider|preview|embed)",
    re.IGNORECASE,
)


def _is_bot(user_agent: str) -> bool:
    """Определяет, является ли запрос от бота/краулера."""
    if not user_agent:
        return True  # Нет UA — скорее всего не браузер
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

# Минимальная страница-заглушка для ботов: отдаём OG-мета для красивого
# превью, но без активации. Можно настроить текст/картинку.
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


# ═══════════════════════════════════════
# АКТИВАЦИЯ (публичный)
# ═══════════════════════════════════════

@app.get("/activate/{token}")
async def activate(token: str, request: Request):
    """Клиент переходит по этой ссылке из Telegram-бота."""

    user_agent = request.headers.get("User-Agent", "")

    # ── Блокируем ботов (Telegram preview, Twitter cards и т.д.) ──
    if _is_bot(user_agent):
        logger.info("Bot blocked: token=%s...%s ua=%s", token[:6], token[-4:], user_agent[:80])
        return HTMLResponse(TMPL_BOT, status_code=200)

    # Определяем реальный IP
    client_ip = (
        request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.client.host
    )

    # Валидация IPv4
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

    # Активация в БД
    result = activate_client(token, client_ip, user_agent)

    if "error" in result:
        return _error_html(result["error"])

    # Уже активен с этим IP
    if result["status"] == "already_active":
        return HTMLResponse(TMPL_SAME.format(style=_BASE_STYLE, ip=client_ip))

    # IP изменился — обновляем relay
    old_ip = result.get("old_ip")
    new_ip = result["new_ip"]
    logger.info("Client #%d: %s → %s", result["client_id"], old_ip or "new", new_ip)

    relay_results = await relay_client.add_ip(new_ip, old_ip)
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
    # Убираем приватные поля
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


@app.patch("/api/clients/{client_id}/block", dependencies=[Depends(require_api_key)])
async def api_block_client(client_id: int, data: ClientBlock):
    client = get_client_by_id(client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    block_client(client_id, data.blocked)

    # Блокировка → удаляем IP с relay
    if data.blocked and client["current_ip"]:
        await relay_client.remove_ip(client["current_ip"])

    return {"id": client_id, "is_blocked": data.blocked}


@app.delete("/api/clients/{client_id}", dependencies=[Depends(require_api_key)])
async def api_delete_client(client_id: int):
    client = delete_client(client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    if client["current_ip"]:
        await relay_client.remove_ip(client["current_ip"])

    return {"deleted": True, "id": client_id}


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


@app.post("/api/relays/{relay_id}/sync", dependencies=[Depends(require_api_key)])
async def api_sync_relay(relay_id: int):
    return await relay_client.full_sync(relay_id=relay_id)


@app.post("/api/relays/sync-all", dependencies=[Depends(require_api_key)])
async def api_sync_all():
    return await relay_client.full_sync()


@app.get("/api/relays/health-all", dependencies=[Depends(require_api_key)])
async def api_health_all():
    return await relay_client.health_check_all()


# ═══════════════════════════════════════
# API: СТАТИСТИКА
# ═══════════════════════════════════════

@app.get("/api/stats", dependencies=[Depends(require_api_key)])
async def api_stats():
    clients = list_clients()
    relays = list_relays()
    return {
        "total_clients": len(clients),
        "active_clients": len([c for c in clients if c["current_ip"] and not c["is_blocked"]]),
        "blocked_clients": len([c for c in clients if c["is_blocked"]]),
        "total_relays": len(relays),
        "active_relays": len([r for r in relays if r["is_active"]]),
    }


# ═══════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}