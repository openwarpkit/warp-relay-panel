#!/usr/bin/env python3
"""
WARP Relay Agent — лёгкий HTTP-сервис на каждом relay-сервере.
Принимает команды от панели для управления ipset whitelist.
Отдаёт /health и /stats для мониторинга.

Запуск: python3 agent.py
Конфиг: .env рядом с agent.py или переменные окружения
"""

import os
import re
import subprocess
import time
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

load_dotenv()

AGENT_SECRET = os.environ.get("AGENT_SECRET", "change-me")
AGENT_PORT = int(os.environ.get("AGENT_PORT", "7580"))
IPSET_NAME = os.environ.get("IPSET_NAME", "warp_whitelist")

app = FastAPI(title="WARP Relay Agent", version="1.0.0")

# ═══════════════════════════════════════
# AUTH
# ═══════════════════════════════════════

def verify_secret(request: Request):
    key = request.headers.get("X-Agent-Key", "")
    if key != AGENT_SECRET:
        raise HTTPException(403, "Invalid agent key")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # /health без авторизации (для внешних мониторингов)
    if request.url.path == "/health":
        return await call_next(request)
    verify_secret(request)
    return await call_next(request)


# ═══════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _valid_ip(ip: str) -> bool:
    return bool(_IP_RE.match(ip))


def _run(cmd: str, check: bool = False) -> tuple[int, str, str]:
    """Запускает shell-команду, возвращает (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=10,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr}")
    return result.returncode, result.stdout.strip(), result.stderr.strip()


# ═══════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════

class IPRequest(BaseModel):
    ip: str

class IPUpdateRequest(BaseModel):
    new_ip: str
    old_ip: str | None = None

class SyncRequest(BaseModel):
    ips: list[str]


# ═══════════════════════════════════════
# WHITELIST ENDPOINTS
# ═══════════════════════════════════════

@app.post("/whitelist/update")
async def whitelist_update(data: IPUpdateRequest):
    """Добавить новый IP, удалить старый, убить conntrack."""
    if not _valid_ip(data.new_ip):
        raise HTTPException(400, f"Invalid new_ip: {data.new_ip}")
    if data.old_ip and not _valid_ip(data.old_ip):
        raise HTTPException(400, f"Invalid old_ip: {data.old_ip}")

    removed = None
    if data.old_ip:
        _run(f"ipset del {IPSET_NAME} {data.old_ip} 2>/dev/null")
        _run(f"conntrack -D -p udp -s {data.old_ip} 2>/dev/null")
        removed = data.old_ip

    _run(f"ipset add {IPSET_NAME} {data.new_ip} 2>/dev/null")

    return {"added": data.new_ip, "removed": removed}


@app.post("/whitelist/remove")
async def whitelist_remove(data: IPRequest):
    """Удалить IP из whitelist + убить conntrack."""
    if not _valid_ip(data.ip):
        raise HTTPException(400, f"Invalid ip: {data.ip}")

    _run(f"ipset del {IPSET_NAME} {data.ip} 2>/dev/null")
    _run(f"conntrack -D -p udp -s {data.ip} 2>/dev/null")

    return {"removed": data.ip}


@app.post("/whitelist/sync")
async def whitelist_sync(data: SyncRequest):
    """Полная синхронизация: очистить ipset и добавить все IP заново."""
    # Валидация всех IP
    valid_ips = [ip for ip in data.ips if _valid_ip(ip)]
    invalid = [ip for ip in data.ips if not _valid_ip(ip)]

    _run(f"ipset create {IPSET_NAME} hash:ip 2>/dev/null")
    _run(f"ipset flush {IPSET_NAME}", check=True)

    for ip in valid_ips:
        _run(f"ipset add {IPSET_NAME} {ip}")

    # Сохраняем для автозагрузки
    _run("ipset save > /etc/ipset.rules 2>/dev/null")

    return {"synced": len(valid_ips), "invalid": invalid}


@app.get("/whitelist/list")
async def whitelist_list():
    """Текущее содержимое ipset."""
    code, stdout, _ = _run(f"ipset list {IPSET_NAME} 2>/dev/null")
    if code != 0:
        return {"ips": [], "error": "ipset not found"}

    ips = []
    in_members = False
    for line in stdout.split("\n"):
        if line.startswith("Members:"):
            in_members = True
            continue
        if in_members and line.strip():
            ips.append(line.strip())

    return {"ips": ips, "count": len(ips)}


# ═══════════════════════════════════════
# HEALTH & STATS
# ═══════════════════════════════════════

_START_TIME = time.time()


@app.get("/health")
async def health():
    """Базовая проверка здоровья (без авторизации)."""
    # IP forward
    fwd = "0"
    try:
        fwd = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except Exception:
        pass

    # ipset count
    code, stdout, _ = _run(f"ipset list {IPSET_NAME} 2>/dev/null | grep -c '^[0-9]'")
    ipset_count = int(stdout) if code == 0 and stdout.isdigit() else 0

    # conntrack
    ct_cur = "0"
    ct_max = "0"
    try:
        ct_cur = Path("/proc/sys/net/netfilter/nf_conntrack_count").read_text().strip()
        ct_max = Path("/proc/sys/net/netfilter/nf_conntrack_max").read_text().strip()
    except Exception:
        pass

    # Load
    load = "0"
    try:
        load = Path("/proc/loadavg").read_text().strip().split()[0]
    except Exception:
        pass

    # Memory
    mem_total = mem_used = 0
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                meminfo[parts[0].rstrip(":")] = int(parts[1])
            mem_total = meminfo.get("MemTotal", 0)
            mem_available = meminfo.get("MemAvailable", 0)
            mem_used = mem_total - mem_available
    except Exception:
        pass

    return {
        "status": "ok",
        "uptime_seconds": int(time.time() - _START_TIME),
        "ip_forward": fwd == "1",
        "ipset_count": ipset_count,
        "conntrack": f"{ct_cur}/{ct_max}",
        "load": float(load),
        "memory_mb": {
            "used": round(mem_used / 1024),
            "total": round(mem_total / 1024),
        },
    }


@app.get("/stats")
async def stats():
    """Расширенная статистика: клиенты, трафик, порты."""

    # Уникальные клиенты из conntrack
    code, stdout, _ = _run(
        "conntrack -L -p udp 2>/dev/null | grep -oP '^.*?src=\\K[0-9.]+' | "
        "grep -v '^162\\.159\\.' | sort -u"
    )
    unique_clients = [ip for ip in stdout.split("\n") if ip.strip()] if code == 0 else []

    # Conntrack stats
    _, ct_data, _ = _run("conntrack -L -p udp 2>/dev/null | grep -v 'dport=22'")
    ct_lines = ct_data.split("\n") if ct_data else []
    assured = sum(1 for l in ct_lines if "ASSURED" in l)
    unreplied = sum(1 for l in ct_lines if "UNREPLIED" in l)

    # Top портов
    _, ports_raw, _ = _run(
        "conntrack -L -p udp 2>/dev/null | grep -oP 'dport=\\K[0-9]+' | "
        "sort | uniq -c | sort -rn | head -10"
    )
    top_ports = {}
    for line in ports_raw.split("\n"):
        line = line.strip()
        if line:
            parts = line.split()
            if len(parts) == 2:
                top_ports[parts[1]] = int(parts[0])

    # Трафик из iptables
    _, traffic_raw, _ = _run(
        "iptables -L FORWARD -n -v 2>/dev/null | grep -E 'WR_|warp_whitelist'"
    )

    # Интерфейс: скорость
    _, iface, _ = _run("ip route | awk '/default/ {print $5; exit}'")
    speed = {}
    if iface:
        try:
            rx1 = int(Path(f"/sys/class/net/{iface}/statistics/rx_bytes").read_text())
            tx1 = int(Path(f"/sys/class/net/{iface}/statistics/tx_bytes").read_text())
            speed = {"interface": iface, "rx_bytes_total": rx1, "tx_bytes_total": tx1}
        except Exception:
            pass

    return {
        "unique_clients": len(unique_clients),
        "client_ips": unique_clients,
        "sessions": {"assured": assured, "unreplied": unreplied},
        "top_ports": top_ports,
        "network": speed,
    }


# ═══════════════════════════════════════
# RUN
# ═══════════════════════════════════════

if __name__ == "__main__":
    print(f"WARP Relay Agent starting on :{AGENT_PORT}")
    print(f"ipset: {IPSET_NAME}")
    uvicorn.run(app, host="0.0.0.0", port=AGENT_PORT, log_level="info")