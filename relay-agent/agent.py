#!/usr/bin/env python3
"""
— ipset whitelist с refcount-защитой общих IP
— трафик по IP (для админского анализа)

Refcount: агент знает сколько client_id сидят на каждом IP.
  Даже если панель ошибётся — агент не удалит IP пока хоть
  один клиент на нём остаётся.

Трафик: conntrack byte counters по IP, хранится в traffic.json,
  автосброс 1-го числа месяца.
"""

import asyncio
import json
import os
import re
import subprocess
import time
import logging
from collections import defaultdict
from datetime import datetime, date, timezone
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

load_dotenv()

AGENT_SECRET = os.environ.get("AGENT_SECRET", "change-me")
AGENT_PORT = int(os.environ.get("AGENT_PORT", "7580"))
IPSET_NAME = os.environ.get("IPSET_NAME", "warp_whitelist")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/opt/warp-relay-agent"))
TRAFFIC_FILE = DATA_DIR / "traffic.json"
REFCOUNT_FILE = DATA_DIR / "refcount.json"
TRAFFIC_INTERVAL = int(os.environ.get("TRAFFIC_INTERVAL", "30"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("agent")

version = "1.2.0"
app = FastAPI(title="WARP Relay Agent", version=version)


# ═══════════════════════════════════════
# AUTH
# ═══════════════════════════════════════

def verify_secret(request: Request):
    key = request.headers.get("X-Agent-Key", "")
    if key != AGENT_SECRET:
        raise HTTPException(403, "Invalid agent key")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path == "/health":
        return await call_next(request)
    verify_secret(request)
    return await call_next(request)


# ═══════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

_CT_RE = re.compile(
    r"src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)\s+"
    r"packets=\d+\s+bytes=(\d+)\s+"
    r"src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)\s+"
    r"packets=\d+\s+bytes=(\d+)"
)


def _valid_ip(ip: str) -> bool:
    return bool(_IP_RE.match(ip))


def _run(cmd: str, check: bool = False) -> tuple[int, str, str]:
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=10,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr}")
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _format_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# ═══════════════════════════════════════
# REFCOUNT MAP  (IP → {set of client_ids})
# ═══════════════════════════════════════

class RefCountMap:
    """
    IP → set(client_ids). Страховка от удаления общего IP.

    Если два клиента (id=1, id=2) имеют один IP 1.2.3.4:
      refcount["1.2.3.4"] = {1, 2}

    При удалении клиента 2: refcount["1.2.3.4"] = {1}
    IP остаётся в ipset, потому что refcount > 0.

    При удалении клиента 1: refcount["1.2.3.4"] = {}
    Теперь IP удаляется из ipset.
    """

    def __init__(self):
        self._map: dict[str, set[int]] = defaultdict(set)
        self._load()

    def _load(self):
        try:
            data = json.loads(REFCOUNT_FILE.read_text())
            for ip, cids in data.items():
                self._map[ip] = set(cids)
            logger.info("Refcount loaded: %d IPs", len(self._map))
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning("Could not load refcount: %s", e)

    def _save(self):
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            # set → list для JSON
            data = {ip: sorted(cids) for ip, cids in self._map.items() if cids}
            REFCOUNT_FILE.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error("Could not save refcount: %s", e)

    def add(self, ip: str, client_id: int, old_ip: str | None = None) -> bool:
        """
        Клиент перешёл на новый IP.
        Returns: True если old_ip можно безопасно удалить из ipset.
        """
        # Убираем клиента со старого IP
        can_remove_old = False
        if old_ip and old_ip in self._map:
            self._map[old_ip].discard(client_id)
            if not self._map[old_ip]:
                del self._map[old_ip]
                can_remove_old = True

        # Добавляем на новый
        self._map[ip].add(client_id)
        self._save()
        return can_remove_old

    def remove_client(self, ip: str, client_id: int | None = None) -> bool:
        """
        Удалить клиента с IP.
        Если client_id=None — считаем что удаляем "по IP" без привязки.
        Returns: True если IP можно безопасно удалить из ipset.
        """
        if ip not in self._map:
            return True  # IP не в маппинге — безопасно удалять

        if client_id is not None:
            self._map[ip].discard(client_id)
        else:
            # Без client_id — удаляем весь IP
            self._map[ip].clear()

        can_remove = not self._map[ip]
        if can_remove:
            del self._map[ip]

        self._save()
        return can_remove

    def set_all(self, entries: list[tuple[str, int]]):
        """Полная замена при sync."""
        self._map.clear()
        for ip, cid in entries:
            self._map[ip].add(cid)
        self._save()

    def count(self, ip: str) -> int:
        return len(self._map.get(ip, set()))

    def get_all(self) -> dict[str, list[int]]:
        return {ip: sorted(cids) for ip, cids in self._map.items() if cids}


refcount = RefCountMap()


# ═══════════════════════════════════════
# TRAFFIC MONITOR (по IP)
# ═══════════════════════════════════════

class TrafficMonitor:
    """
    Трафик по IP для админского анализа.
    conntrack byte counters, дельта каждые N секунд.
    """

    def __init__(self):
        self.interval = TRAFFIC_INTERVAL
        self._last_conns: dict[tuple, tuple[int, int]] = {}
        self.traffic = self._load()
        self._enable_accounting()

    def _enable_accounting(self):
        code, _, _ = _run("sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null")
        if code == 0:
            logger.info("conntrack accounting enabled")
        else:
            logger.warning("Could not enable conntrack accounting")

    def _load(self) -> dict:
        try:
            data = json.loads(TRAFFIC_FILE.read_text())
            if "month" in data and "ips" in data:
                logger.info("Traffic loaded: month=%s, IPs=%d",
                            data["month"], len(data["ips"]))
                return data
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning("Could not load traffic data: %s", e)
        return self._empty()

    def _empty(self) -> dict:
        return {
            "month": date.today().strftime("%Y-%m"),
            "ips": {},
            "last_reset": datetime.now(timezone.utc).isoformat(),
        }

    def _save(self):
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            TRAFFIC_FILE.write_text(json.dumps(self.traffic, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.error("Could not save traffic data: %s", e)

    def _check_month_reset(self):
        current_month = date.today().strftime("%Y-%m")
        if self.traffic.get("month") != current_month:
            logger.info("Monthly reset: %s → %s",
                        self.traffic.get("month", "?"), current_month)
            self.traffic = self._empty()
            self._last_conns.clear()
            self._save()

    def _snapshot(self) -> tuple[dict, dict]:
        code, stdout, _ = _run("conntrack -L -o extended -p udp 2>/dev/null")
        if code != 0 or not stdout:
            return {}, {}

        conns = {}
        conn_ips = {}

        for line in stdout.split("\n"):
            m = _CT_RE.search(line)
            if not m:
                continue

            src1 = m.group(1)
            dst1 = m.group(2)
            sport1 = m.group(3)
            dport1 = m.group(4)
            bytes_orig = int(m.group(5))
            bytes_reply = int(m.group(10))

            if src1.startswith("162.159.") or src1.startswith("172."):
                continue
            if dport1 == "22" or sport1 == "22":
                continue

            key = (src1, dst1, sport1, dport1)
            conns[key] = (bytes_orig, bytes_reply)
            conn_ips[key] = src1

        return conns, conn_ips

    def collect(self):
        self._check_month_reset()

        current_conns, conn_ips = self._snapshot()
        now = datetime.now(timezone.utc).isoformat()
        changed = False

        for key, (orig_bytes, reply_bytes) in current_conns.items():
            ip = conn_ips[key]

            if key in self._last_conns:
                prev_orig, prev_reply = self._last_conns[key]
                delta_tx = max(0, orig_bytes - prev_orig)
                delta_rx = max(0, reply_bytes - prev_reply)
            else:
                delta_tx = 0
                delta_rx = 0

            if delta_tx > 0 or delta_rx > 0:
                entry = self.traffic["ips"].setdefault(ip, {"tx": 0, "rx": 0})
                entry["tx"] += delta_tx
                entry["rx"] += delta_rx
                entry["updated"] = now
                changed = True

        self._last_conns = current_conns

        if changed:
            self._save()

    def get_all(self) -> dict:
        self._check_month_reset()
        result = {
            "month": self.traffic["month"],
            "last_reset": self.traffic.get("last_reset"),
            "ips": {},
        }
        total_tx = total_rx = 0

        for ip, stats in self.traffic.get("ips", {}).items():
            tx = stats.get("tx", 0)
            rx = stats.get("rx", 0)
            total_tx += tx
            total_rx += rx
            # Добавляем refcount — сколько клиентов на этом IP
            rc = refcount.count(ip)
            result["ips"][ip] = {
                "tx_bytes": tx,
                "rx_bytes": rx,
                "total_bytes": tx + rx,
                "tx_human": _format_bytes(tx),
                "rx_human": _format_bytes(rx),
                "total_human": _format_bytes(tx + rx),
                "clients_on_ip": rc,
                "updated": stats.get("updated"),
            }

        result["total_tx_bytes"] = total_tx
        result["total_rx_bytes"] = total_rx
        result["total_bytes"] = total_tx + total_rx
        result["total_tx"] = _format_bytes(total_tx)
        result["total_rx"] = _format_bytes(total_rx)
        result["total"] = _format_bytes(total_tx + total_rx)
        result["ip_count"] = len(result["ips"])
        return result

    def get_ip(self, ip: str) -> dict | None:
        stats = self.traffic.get("ips", {}).get(ip)
        if not stats:
            return None
        tx = stats.get("tx", 0)
        rx = stats.get("rx", 0)
        rc = refcount.count(ip)
        return {
            "ip": ip,
            "month": self.traffic["month"],
            "tx_bytes": tx,
            "rx_bytes": rx,
            "total_bytes": tx + rx,
            "tx_human": _format_bytes(tx),
            "rx_human": _format_bytes(rx),
            "total_human": _format_bytes(tx + rx),
            "clients_on_ip": rc,
            "client_ids": sorted(refcount._map.get(ip, set())),
            "updated": stats.get("updated"),
        }

    def reset(self):
        self.traffic = self._empty()
        self._last_conns.clear()
        self._save()
        logger.info("Traffic data manually reset")


traffic_monitor = TrafficMonitor()


# ═══════════════════════════════════════
# BACKGROUND TASK
# ═══════════════════════════════════════

async def _traffic_collector_loop():
    logger.info("Traffic collector started (interval=%ds)", traffic_monitor.interval)
    try:
        traffic_monitor.collect()
    except Exception as e:
        logger.error("Traffic collector init error: %s", e)

    while True:
        await asyncio.sleep(traffic_monitor.interval)
        try:
            traffic_monitor.collect()
        except Exception as e:
            logger.error("Traffic collector error: %s", e)


@app.on_event("startup")
async def on_startup():
    asyncio.create_task(_traffic_collector_loop())


# ═══════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════

class IPRequest(BaseModel):
    ip: str

class IPUpdateRequest(BaseModel):
    new_ip: str
    old_ip: str | None = None
    client_id: int | None = None

class SyncClientEntry(BaseModel):
    ip: str
    client_id: int

class SyncRequest(BaseModel):
    clients: list[SyncClientEntry]


# ═══════════════════════════════════════
# WHITELIST ENDPOINTS
# ═══════════════════════════════════════

@app.post("/whitelist/update")
async def whitelist_update(data: IPUpdateRequest):
    """
    Добавить/обновить IP в whitelist.
    Двойная защита: панель уже проверила shared IP,
    агент дополнительно проверяет через refcount.
    """
    if not _valid_ip(data.new_ip):
        raise HTTPException(400, f"Invalid new_ip: {data.new_ip}")
    if data.old_ip and not _valid_ip(data.old_ip):
        raise HTTPException(400, f"Invalid old_ip: {data.old_ip}")

    removed = None

    if data.client_id is not None:
        # Обновляем refcount и проверяем можно ли удалять old_ip
        can_remove = refcount.add(data.new_ip, data.client_id, data.old_ip)

        if data.old_ip and can_remove:
            _run(f"ipset del {IPSET_NAME} {data.old_ip} 2>/dev/null")
            _run(f"conntrack -D -p udp -s {data.old_ip} 2>/dev/null")
            removed = data.old_ip
        elif data.old_ip and not can_remove:
            rc = refcount.count(data.old_ip)
            logger.info("Keeping %s in ipset (refcount=%d)", data.old_ip, rc)
    else:
        # Без client_id — старое поведение (удаляем old_ip если передан)
        if data.old_ip:
            _run(f"ipset del {IPSET_NAME} {data.old_ip} 2>/dev/null")
            _run(f"conntrack -D -p udp -s {data.old_ip} 2>/dev/null")
            removed = data.old_ip

    _run(f"ipset add {IPSET_NAME} {data.new_ip} 2>/dev/null")

    return {
        "added": data.new_ip,
        "removed": removed,
        "client_id": data.client_id,
        "refcount": refcount.count(data.new_ip),
    }


@app.post("/whitelist/remove")
async def whitelist_remove(data: IPRequest):
    """Удалить IP. Проверяет refcount — не удаляет если кто-то ещё использует."""
    if not _valid_ip(data.ip):
        raise HTTPException(400, f"Invalid ip: {data.ip}")

    can_remove = refcount.remove_client(data.ip)

    if can_remove:
        _run(f"ipset del {IPSET_NAME} {data.ip} 2>/dev/null")
        _run(f"conntrack -D -p udp -s {data.ip} 2>/dev/null")
        return {"removed": data.ip}
    else:
        rc = refcount.count(data.ip)
        logger.info("Keeping %s in ipset (refcount=%d)", data.ip, rc)
        return {"removed": None, "kept": data.ip, "refcount": rc}


@app.post("/whitelist/sync")
async def whitelist_sync(data: SyncRequest):
    """Полная синхронизация: ipset + refcount."""
    valid_entries = [e for e in data.clients if _valid_ip(e.ip)]
    invalid = [e.ip for e in data.clients if not _valid_ip(e.ip)]

    _run(f"ipset create {IPSET_NAME} hash:ip 2>/dev/null")
    _run(f"ipset flush {IPSET_NAME}", check=True)

    # Собираем уникальные IP и обновляем refcount
    unique_ips = set()
    rc_entries = []
    for entry in valid_entries:
        unique_ips.add(entry.ip)
        rc_entries.append((entry.ip, entry.client_id))

    for ip in unique_ips:
        _run(f"ipset add {IPSET_NAME} {ip}")

    refcount.set_all(rc_entries)

    _run("ipset save > /etc/ipset.rules 2>/dev/null")

    return {
        "synced": len(unique_ips),
        "clients": len(valid_entries),
        "invalid": invalid,
    }


@app.get("/whitelist/list")
async def whitelist_list():
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
# TRAFFIC ENDPOINTS (по IP)
# ═══════════════════════════════════════

@app.get("/traffic")
async def traffic_all():
    """Потребление трафика по всем IP за текущий месяц."""
    return traffic_monitor.get_all()


@app.get("/traffic/{ip}")
async def traffic_by_ip(ip: str):
    """Потребление трафика конкретного IP."""
    if not _valid_ip(ip):
        raise HTTPException(400, f"Invalid IP: {ip}")
    result = traffic_monitor.get_ip(ip)
    if not result:
        return {
            "ip": ip,
            "month": traffic_monitor.traffic["month"],
            "tx_bytes": 0, "rx_bytes": 0, "total_bytes": 0,
            "tx_human": "0 B", "rx_human": "0 B", "total_human": "0 B",
            "clients_on_ip": refcount.count(ip),
            "client_ids": sorted(refcount._map.get(ip, set())),
            "updated": None,
        }
    return result


@app.post("/traffic/reset")
async def traffic_reset():
    """Принудительный сброс данных трафика."""
    traffic_monitor.reset()
    return {"ok": True, "month": traffic_monitor.traffic["month"]}


# ═══════════════════════════════════════
# REFCOUNT (для отладки)
# ═══════════════════════════════════════

@app.get("/refcount")
async def refcount_list():
    """Текущий refcount-маппинг (IP → client_ids)."""
    return refcount.get_all()


# ═══════════════════════════════════════
# HEALTH & STATS
# ═══════════════════════════════════════

_START_TIME = time.time()


@app.get("/health")
async def health():
    fwd = "0"
    try:
        fwd = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except Exception:
        pass

    code, stdout, _ = _run(f"ipset list {IPSET_NAME} 2>/dev/null | grep -c '^[0-9]'")
    ipset_count = int(stdout) if code == 0 and stdout.isdigit() else 0

    ct_cur = ct_max = "0"
    try:
        ct_cur = Path("/proc/sys/net/netfilter/nf_conntrack_count").read_text().strip()
        ct_max = Path("/proc/sys/net/netfilter/nf_conntrack_max").read_text().strip()
    except Exception:
        pass

    load = "0"
    try:
        load = Path("/proc/loadavg").read_text().strip().split()[0]
    except Exception:
        pass

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

    t = traffic_monitor.get_all()

    return {
        "status": "ok",
        "version": version,
        "uptime_seconds": int(time.time() - _START_TIME),
        "ip_forward": fwd == "1",
        "ipset_count": ipset_count,
        "conntrack": f"{ct_cur}/{ct_max}",
        "load": float(load),
        "memory_mb": {
            "used": round(mem_used / 1024),
            "total": round(mem_total / 1024),
        },
        "traffic_month": t["month"],
        "traffic_total": t["total"],
        "traffic_ips": t["ip_count"],
    }


@app.get("/stats")
async def stats():
    code, stdout, _ = _run(
        "conntrack -L -p udp 2>/dev/null | grep -oP '^.*?src=\\K[0-9.]+' | "
        "grep -v '^162\\.159\\.' | sort -u"
    )
    unique_clients = [ip for ip in stdout.split("\n") if ip.strip()] if code == 0 else []

    _, ct_data, _ = _run("conntrack -L -p udp 2>/dev/null | grep -v 'dport=22'")
    ct_lines = ct_data.split("\n") if ct_data else []
    assured = sum(1 for l in ct_lines if "ASSURED" in l)
    unreplied = sum(1 for l in ct_lines if "UNREPLIED" in l)

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
        "traffic": traffic_monitor.get_all(),
    }


# ═══════════════════════════════════════
# RUN
# ═══════════════════════════════════════

if __name__ == "__main__":
    print(f"WARP Relay Agent v1.1.0 starting on :{AGENT_PORT}")
    print(f"ipset: {IPSET_NAME}")
    print(f"Traffic: every {TRAFFIC_INTERVAL}s → {TRAFFIC_FILE}")
    print(f"Refcount: {REFCOUNT_FILE}")
    uvicorn.run(app, host="0.0.0.0", port=AGENT_PORT, log_level="info")