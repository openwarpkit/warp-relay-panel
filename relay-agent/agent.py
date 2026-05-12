#!/usr/bin/env python3
"""
WARP Relay Agent v1.3.0

— ipset whitelist с refcount-защитой общих IP
— трафик по IP (conntrack accounting)
— точный онлайн (ipset ∩ conntrack ASSURED)
— самообновление через /update (fire-and-forget)
— фоновая синхронизация whitelist через /whitelist/sync (fire-and-forget)
— self-heal watchdog: периодически восстанавливает потерянные iptables/ipset
— rate-limit per IP (CONNMARK + HTB), симметричный
— расширенный /health: CPU%, RAM, диск, сеть, agent-process, last_self_heal
"""

import asyncio
import json
import os
import re
import signal
import subprocess
import time
import logging
from collections import defaultdict
from datetime import datetime, date, timezone, timedelta
from pathlib import Path

import psutil
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

load_dotenv()

AGENT_SECRET = os.environ.get("AGENT_SECRET", "change-me")
AGENT_PORT = int(os.environ.get("AGENT_PORT", "7580"))
IPSET_NAME = os.environ.get("IPSET_NAME", "warp_whitelist")
DATA_DIR = Path(os.environ.get("DATA_DIR", "/opt/warp-relay-agent"))
REPO_DIR = Path(os.environ.get("REPO_DIR", "/opt/warp-relay-panel"))
TRAFFIC_FILE = DATA_DIR / "traffic.json"
REFCOUNT_FILE = DATA_DIR / "refcount.json"
UPDATE_STATUS_FILE = DATA_DIR / "update_status.json"
SYNC_STATUS_FILE = DATA_DIR / "sync_status.json"
SELF_HEAL_FILE = DATA_DIR / "self_heal_status.json"
RATE_LIMITS_FILE = DATA_DIR / "rate_limits.json"
RULES_RECIPE_FILE = DATA_DIR / "rules_recipe.json"
ENSURE_RULES_SCRIPT = DATA_DIR / "ensure_rules.sh"

TRAFFIC_INTERVAL = int(os.environ.get("TRAFFIC_INTERVAL", "30"))
RULES_WATCHDOG_INTERVAL = int(os.environ.get("RULES_WATCHDOG_INTERVAL", "30"))
METRICS_SAMPLE_INTERVAL = int(os.environ.get("METRICS_SAMPLE_INTERVAL", "1"))
IPSET_PERSIST_DEBOUNCE = float(os.environ.get("IPSET_PERSIST_DEBOUNCE", "3.0"))

PANEL_URL = os.environ.get("PANEL_URL", "").rstrip("/")
PANEL_API_KEY = os.environ.get("PANEL_API_KEY", "")
RELAY_ID = os.environ.get("RELAY_ID", "")

# Диапазон fwmark'ов для rate-limit'ов: 10..998 (999 = default class)
RATE_LIMIT_MARK_MIN = 10
RATE_LIMIT_MARK_MAX = 998

MSK = timezone(timedelta(hours=3))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("agent")

AGENT_VERSION = "1.3.0"
app = FastAPI(title="WARP Relay Agent", version=AGENT_VERSION)


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


def _run(cmd: str, check: bool = False, timeout: int = 10) -> tuple[int, str, str]:
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\n{result.stderr}")
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def _run_killgroup(cmd: str, timeout: int = 30) -> tuple[int, str, str]:
    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        return -1, "", f"Timed out after {timeout}s"


def _format_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _now_msk() -> datetime:
    return datetime.now(MSK)


def _default_iface() -> str | None:
    code, out, _ = _run("ip route | awk '/default/ {print $5; exit}'")
    return out if code == 0 and out else None


def _get_ipset_members() -> set[str]:
    code, stdout, _ = _run(f"ipset list {IPSET_NAME} 2>/dev/null")
    if code != 0:
        return set()
    ips = set()
    in_members = False
    for line in stdout.split("\n"):
        if line.startswith("Members:"):
            in_members = True
            continue
        if in_members and line.strip():
            ips.add(line.strip())
    return ips


def _get_conntrack_assured_ips() -> set[str]:
    code, stdout, _ = _run(
        "conntrack -L -p udp 2>/dev/null | grep ASSURED | "
        "grep -oP '^.*?src=\\K[0-9.]+' | grep -v '^162\\.159\\.' | sort -u"
    )
    if code != 0 or not stdout:
        return set()
    return {ip for ip in stdout.split("\n") if ip.strip()}


def _get_online_clients() -> dict:
    whitelist = _get_ipset_members()
    assured = _get_conntrack_assured_ips()
    online_ips = whitelist & assured

    online = []
    for ip in sorted(online_ips):
        client_ids = sorted(refcount._map.get(ip, set()))
        online.append({"ip": ip, "client_ids": client_ids})

    return {
        "count": len(online_ips),
        "whitelist_total": len(whitelist),
        "conntrack_assured": len(assured),
        "clients": online,
    }


# ═══════════════════════════════════════
# REFCOUNT MAP
# ═══════════════════════════════════════

class RefCountMap:
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
            data = {ip: sorted(cids) for ip, cids in self._map.items() if cids}
            REFCOUNT_FILE.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error("Could not save refcount: %s", e)

    def add(self, ip: str, client_id: int, old_ip: str | None = None) -> bool:
        can_remove_old = False
        if old_ip and old_ip in self._map:
            self._map[old_ip].discard(client_id)
            if not self._map[old_ip]:
                del self._map[old_ip]
                can_remove_old = True
        self._map[ip].add(client_id)
        self._save()
        return can_remove_old

    def remove_client(self, ip: str, client_id: int | None = None) -> bool:
        if ip not in self._map or not self._map[ip]:
            self._map.pop(ip, None)
            self._save()
            return True
        if client_id is not None:
            self._map[ip].discard(client_id)
        else:
            self._map[ip].clear()
        can_remove = not self._map[ip]
        if can_remove:
            del self._map[ip]
        self._save()
        return can_remove

    def set_all(self, entries: list[tuple[str, int]]):
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
# IPSET PERSIST (debounced)
# ═══════════════════════════════════════

_persist_event: asyncio.Event | None = None  # инициализируется в startup


def _save_ipset_now():
    """Синхронный дамп ipset → /etc/ipset.rules."""
    code, _, err = _run("ipset save > /etc/ipset.rules 2>&1")
    if code != 0:
        logger.warning("ipset save failed: %s", err)


async def _ipset_persist_loop():
    """Дебаунсер: при срабатывании _persist_event ждёт N секунд (если новые
    события — таймер сбрасывается) и затем дампит ipset."""
    global _persist_event
    while True:
        await _persist_event.wait()
        # Drain накопившихся уведомлений в окне debounce
        try:
            while True:
                await asyncio.wait_for(
                    _persist_event.wait(), timeout=IPSET_PERSIST_DEBOUNCE
                )
                _persist_event.clear()
        except asyncio.TimeoutError:
            pass
        _persist_event.clear()
        try:
            await asyncio.to_thread(_save_ipset_now)
            logger.info("ipset persisted to /etc/ipset.rules")
        except Exception as e:
            logger.error("ipset persist error: %s", e)


def _trigger_persist():
    if _persist_event is not None:
        _persist_event.set()


# ═══════════════════════════════════════
# TRAFFIC MONITOR
# ═══════════════════════════════════════

class TrafficMonitor:
    def __init__(self):
        self.interval = TRAFFIC_INTERVAL
        self._last_conns: dict[tuple, tuple[int, int]] = {}
        self.traffic = self._load()
        self._enable_accounting()

    def _enable_accounting(self):
        code, _, _ = _run("sysctl -w net.netfilter.nf_conntrack_acct=1 2>/dev/null")
        if code == 0:
            logger.info("conntrack accounting enabled")

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
            "month": _now_msk().strftime("%Y-%m"),
            "ips": {},
            "last_reset": _now_msk().isoformat(),
        }

    def _save(self):
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            TRAFFIC_FILE.write_text(json.dumps(self.traffic, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.error("Could not save traffic data: %s", e)

    def _check_month_reset(self):
        current_month = _now_msk().strftime("%Y-%m")
        if self.traffic.get("month") != current_month:
            logger.info("Monthly reset (MSK): %s → %s",
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
        now = _now_msk().isoformat()
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
            rc = refcount.count(ip)
            result["ips"][ip] = {
                "tx_bytes": tx, "rx_bytes": rx, "total_bytes": tx + rx,
                "tx_human": _format_bytes(tx), "rx_human": _format_bytes(rx),
                "total_human": _format_bytes(tx + rx),
                "clients_on_ip": rc, "updated": stats.get("updated"),
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
            "ip": ip, "month": self.traffic["month"],
            "tx_bytes": tx, "rx_bytes": rx, "total_bytes": tx + rx,
            "tx_human": _format_bytes(tx), "rx_human": _format_bytes(rx),
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
# RATE LIMIT MANAGER
# ═══════════════════════════════════════

class RateLimitManager:
    """
    Симметричный rate-limit per IP через CONNMARK + HTB.

    На каждый IP:
      - mark M ∈ [10..998] (уникальный)
      - iptables -t mangle -A PREROUTING -m conntrack --ctorigsrc IP -j CONNMARK --set-mark M
      - tc class add dev IFACE parent 1: classid 1:M htb rate Nmbit ceil Nmbit
      - tc filter add dev IFACE protocol ip parent 1:0 prio 1 handle M fw flowid 1:M

    POSTROUTING --restore-mark уже стоит (см. ensure_rules.sh) — он восстанавливает
    mark из conntrack на исходящий пакет. tc на egress матчит mark и ставит в class.
    Симметрия: одна conntrack-запись несёт оба направления, mark тоже.
    """

    def __init__(self):
        self._map: dict[str, dict] = {}  # ip → {mbps, mark, expires_at, client_id, applied_at}
        self._used_marks: set[int] = set()
        self._load()

    # ── persist ──

    def _load(self):
        try:
            data = json.loads(RATE_LIMITS_FILE.read_text())
            for ip, info in data.items():
                self._map[ip] = info
                self._used_marks.add(int(info["mark"]))
            logger.info("Rate limits loaded: %d IPs", len(self._map))
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning("Could not load rate_limits: %s", e)

    def _save(self):
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            RATE_LIMITS_FILE.write_text(json.dumps(self._map, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.error("Could not save rate_limits: %s", e)

    # ── mark allocation ──

    def _allocate_mark(self) -> int:
        for m in range(RATE_LIMIT_MARK_MIN, RATE_LIMIT_MARK_MAX + 1):
            if m not in self._used_marks:
                self._used_marks.add(m)
                return m
        raise RuntimeError("No free fwmark in pool 10..998")

    def _release_mark(self, mark: int):
        self._used_marks.discard(int(mark))

    # ── tc / iptables ──

    def _apply_tc(self, ip: str, mbps: float, mark: int) -> tuple[bool, str]:
        iface = _default_iface()
        if not iface:
            return False, "no default interface"

        # iptables CONNMARK для нового conntrack
        rc1, _, _ = _run(
            f"iptables -t mangle -C PREROUTING -m conntrack --ctorigsrc {ip} "
            f"-j CONNMARK --set-mark {mark} 2>/dev/null"
        )
        if rc1 != 0:
            rc, _, err = _run(
                f"iptables -t mangle -A PREROUTING -m conntrack --ctorigsrc {ip} "
                f"-j CONNMARK --set-mark {mark}"
            )
            if rc != 0:
                return False, f"iptables add failed: {err}"

        # tc class
        rc, _, err = _run(
            f"tc class add dev {iface} parent 1: classid 1:{mark} "
            f"htb rate {mbps}mbit ceil {mbps}mbit burst 16k 2>&1"
        )
        if rc != 0 and "exists" not in err.lower() and "file exists" not in err.lower():
            return False, f"tc class failed: {err}"

        # tc filter
        rc, _, err = _run(
            f"tc filter add dev {iface} protocol ip parent 1:0 prio 1 "
            f"handle {mark} fw flowid 1:{mark} 2>&1"
        )
        if rc != 0 and "exists" not in err.lower() and "file exists" not in err.lower():
            return False, f"tc filter failed: {err}"

        # Пометить уже существующие conntrack-флоу с этим src
        _run(f"conntrack -U -s {ip} -p udp --mark {mark} 2>/dev/null")

        return True, ""

    def _remove_tc(self, ip: str, mark: int):
        iface = _default_iface()
        if not iface:
            return

        _run(
            f"iptables -t mangle -D PREROUTING -m conntrack --ctorigsrc {ip} "
            f"-j CONNMARK --set-mark {mark} 2>/dev/null"
        )
        _run(
            f"tc filter del dev {iface} protocol ip parent 1:0 prio 1 "
            f"handle {mark} fw 2>/dev/null"
        )
        _run(f"tc class del dev {iface} classid 1:{mark} 2>/dev/null")
        # Сбросить mark на текущих conntrack-флоу
        _run(f"conntrack -U -s {ip} -p udp --mark 0 2>/dev/null")

    # ── public API ──

    def set_limit(self, ip: str, mbps: float,
                  expires_at: str | None = None,
                  client_id: int | None = None) -> dict:
        # Если уже есть — переиспользуем mark, обновляем mbps
        existing = self._map.get(ip)
        if existing:
            old_mark = int(existing["mark"])
            # удалить старый класс/фильтр и добавить с новой скоростью
            self._remove_tc(ip, old_mark)
            mark = old_mark
        else:
            mark = self._allocate_mark()

        ok, err = self._apply_tc(ip, mbps, mark)
        if not ok:
            if not existing:
                self._release_mark(mark)
            return {"ok": False, "error": err, "ip": ip}

        self._map[ip] = {
            "mbps": float(mbps),
            "mark": mark,
            "expires_at": expires_at,
            "client_id": client_id,
            "applied_at": _now_msk().isoformat(),
        }
        self._save()
        logger.info("Rate-limit applied: %s = %s Mbps (mark=%d, expires=%s)",
                    ip, mbps, mark, expires_at)
        return {"ok": True, **self._map[ip], "ip": ip}

    def remove_limit(self, ip: str) -> dict:
        info = self._map.pop(ip, None)
        if not info:
            return {"ok": False, "error": "not_found", "ip": ip}
        self._remove_tc(ip, int(info["mark"]))
        self._release_mark(int(info["mark"]))
        self._save()
        logger.info("Rate-limit removed: %s (mark=%d)", ip, info["mark"])
        return {"ok": True, "ip": ip, "removed": info}

    def get(self, ip: str) -> dict | None:
        info = self._map.get(ip)
        if not info:
            return None
        return {**info, "ip": ip}

    def all(self) -> list[dict]:
        return [{**info, "ip": ip} for ip, info in self._map.items()]

    def restore_all(self) -> dict:
        """Переприменить все rate-limit'ы (после старта или watchdog)."""
        applied = []
        failed = []
        for ip, info in list(self._map.items()):
            ok, err = self._apply_tc(ip, info["mbps"], int(info["mark"]))
            if ok:
                applied.append(ip)
            else:
                failed.append({"ip": ip, "error": err})
        return {"applied": applied, "failed": failed}

    def verify(self) -> list[str]:
        """Вернуть список IP, для которых tc-класс отсутствует — нужно пересоздать."""
        iface = _default_iface()
        if not iface:
            return []
        code, out, _ = _run(f"tc class show dev {iface} 2>/dev/null")
        if code != 0:
            return list(self._map.keys())
        existing_marks = set()
        for line in out.split("\n"):
            m = re.search(r"class htb 1:(\d+)", line)
            if m:
                existing_marks.add(int(m.group(1)))
        return [ip for ip, info in self._map.items()
                if int(info["mark"]) not in existing_marks]


rate_limits = RateLimitManager()


# ═══════════════════════════════════════
# METRICS SAMPLER (CPU/network)
# ═══════════════════════════════════════

class MetricsSampler:
    """Фоновый сэмплер: CPU% не блокирует /health, network speed считается дельтами."""

    def __init__(self):
        self.interval = METRICS_SAMPLE_INTERVAL
        self._cpu_total: float = 0.0
        self._cpu_per_core: list[float] = []
        self._net_rx_bps: int = 0
        self._net_tx_bps: int = 0
        self._proc = psutil.Process(os.getpid())
        self._proc_cpu: float = 0.0
        self._last_net: tuple[int, int, float] | None = None  # (rx, tx, ts)

    def snapshot(self) -> dict:
        try:
            mem = self._proc.memory_info()
            mem_mb = round(mem.rss / 1024 / 1024, 1)
        except Exception:
            mem_mb = 0
        try:
            num_threads = self._proc.num_threads()
        except Exception:
            num_threads = 0
        try:
            num_fds = self._proc.num_fds() if hasattr(self._proc, "num_fds") else 0
        except Exception:
            num_fds = 0
        return {
            "cpu_percent_total": self._cpu_total,
            "cpu_percent_per_core": self._cpu_per_core,
            "cpu_count": psutil.cpu_count() or 0,
            "network_speed": {
                "rx_bps": self._net_rx_bps,
                "tx_bps": self._net_tx_bps,
                "rx_human": _format_bytes(self._net_rx_bps) + "/s",
                "tx_human": _format_bytes(self._net_tx_bps) + "/s",
            },
            "agent_process": {
                "cpu_percent": self._proc_cpu,
                "memory_mb": mem_mb,
                "num_threads": num_threads,
                "num_fds": num_fds,
            },
        }

    def disk_snapshot(self) -> dict:
        try:
            d = psutil.disk_usage(str(DATA_DIR if DATA_DIR.exists() else "/"))
            return {
                "total_gb": round(d.total / 1024**3, 2),
                "used_gb": round(d.used / 1024**3, 2),
                "free_gb": round(d.free / 1024**3, 2),
                "percent": d.percent,
            }
        except Exception:
            return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0}

    async def loop(self):
        # Прогрев psutil.cpu_percent (первый вызов всегда 0)
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(interval=None, percpu=True)
        try:
            self._proc.cpu_percent(interval=None)
        except Exception:
            pass

        iface = _default_iface()
        while True:
            await asyncio.sleep(self.interval)
            try:
                self._cpu_total = psutil.cpu_percent(interval=None)
                self._cpu_per_core = psutil.cpu_percent(interval=None, percpu=True)
                try:
                    self._proc_cpu = self._proc.cpu_percent(interval=None)
                except Exception:
                    self._proc_cpu = 0.0

                if iface:
                    try:
                        rx = int(Path(f"/sys/class/net/{iface}/statistics/rx_bytes").read_text())
                        tx = int(Path(f"/sys/class/net/{iface}/statistics/tx_bytes").read_text())
                        ts = time.time()
                        if self._last_net is not None:
                            prx, ptx, pts = self._last_net
                            dt = max(0.001, ts - pts)
                            self._net_rx_bps = int(max(0, rx - prx) / dt)
                            self._net_tx_bps = int(max(0, tx - ptx) / dt)
                        self._last_net = (rx, tx, ts)
                    except Exception:
                        pass
            except Exception as e:
                logger.warning("Metrics sampler error: %s", e)


metrics_sampler = MetricsSampler()


# ═══════════════════════════════════════
# SELF-HEAL WATCHDOG
# ═══════════════════════════════════════

def _load_self_heal_status() -> dict | None:
    try:
        return json.loads(SELF_HEAL_FILE.read_text())
    except Exception:
        return None


def _save_self_heal_status(status: dict):
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        SELF_HEAL_FILE.write_text(json.dumps(status, indent=2))
    except Exception as e:
        logger.error("Could not save self_heal_status: %s", e)


def _check_rules() -> dict:
    """Возвращает dict: {ipset_ok, nat_ok, forward_ok, ip_forward_ok, htb_ok}"""
    ipset_ok = _run(f"ipset list {IPSET_NAME} 2>/dev/null")[0] == 0

    nat_code, nat_out, _ = _run("iptables -t nat -S 2>/dev/null")
    nat_ok = nat_code == 0 and "WR_RULE" in nat_out

    fwd_code, fwd_out, _ = _run("iptables -S FORWARD 2>/dev/null")
    forward_ok = (fwd_code == 0
                  and "WR_WHITELIST_OUT" in fwd_out
                  and "WR_WHITELIST_IN" in fwd_out)

    fwd_val = "0"
    try:
        fwd_val = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except Exception:
        pass
    ip_forward_ok = (fwd_val == "1")

    iface = _default_iface()
    htb_ok = True
    if iface:
        code, out, _ = _run(f"tc qdisc show dev {iface} 2>/dev/null")
        htb_ok = (code == 0 and "qdisc htb 1:" in out)

    return {
        "ipset": ipset_ok,
        "nat": nat_ok,
        "forward": forward_ok,
        "ip_forward": ip_forward_ok,
        "htb": htb_ok,
    }


def _heal(checks: dict) -> list[str]:
    """Выполнить восстановление того, что сломано. Возвращает список действий."""
    actions = []

    if not checks["ipset"] or not checks["nat"] or not checks["forward"] or not checks["htb"]:
        if ENSURE_RULES_SCRIPT.exists():
            actions.append("ran ensure_rules.sh")
            _run(f"bash {ENSURE_RULES_SCRIPT} 2>&1", timeout=60)
        else:
            logger.error("ensure_rules.sh not found at %s", ENSURE_RULES_SCRIPT)

    if not checks["ip_forward"]:
        _run("sysctl -w net.ipv4.ip_forward=1 2>/dev/null")
        actions.append("enabled ip_forward")

    # Если ipset был восстановлен — пересобрать его из refcount как single-source
    after = _check_rules()
    if after["ipset"]:
        in_set = _get_ipset_members()
        expected = set(refcount._map.keys())
        missing = expected - in_set
        if missing:
            for ip in missing:
                _run(f"ipset add {IPSET_NAME} {ip} 2>/dev/null")
            actions.append(f"re-added {len(missing)} IPs to ipset from refcount")
            _save_ipset_now()

    # Проверка целостности rate-limit'ов
    broken_rl = rate_limits.verify()
    if broken_rl:
        result = rate_limits.restore_all()
        actions.append(f"restored {len(result['applied'])} rate-limits")

    return actions


async def _rules_watchdog_loop():
    logger.info("Rules watchdog started (interval=%ds)", RULES_WATCHDOG_INTERVAL)
    while True:
        await asyncio.sleep(RULES_WATCHDOG_INTERVAL)
        try:
            checks = await asyncio.to_thread(_check_rules)
            broken = [k for k, v in checks.items() if not v]
            if broken:
                logger.warning("Self-heal: broken=%s", broken)
                actions = await asyncio.to_thread(_heal, checks)
                _save_self_heal_status({
                    "timestamp": _now_msk().isoformat(),
                    "broken": broken,
                    "actions": actions,
                })
                logger.info("Self-heal actions: %s", actions)
        except Exception as e:
            logger.error("Watchdog error: %s", e)


# ═══════════════════════════════════════
# STARTUP RESYNC FROM PANEL
# ═══════════════════════════════════════

async def _startup_resync():
    """Опционально: дёргает панель за актуальным whitelist + rate_limits."""
    if not (PANEL_URL and PANEL_API_KEY and RELAY_ID):
        logger.info("Startup-resync пропущен (PANEL_URL/PANEL_API_KEY/RELAY_ID не заданы)")
        return
    url = f"{PANEL_URL}/api/relays/{RELAY_ID}/whitelist-payload"
    try:
        async with httpx.AsyncClient(timeout=20.0) as cli:
            r = await cli.get(url, headers={"X-API-Key": PANEL_API_KEY})
            if r.status_code != 200:
                logger.warning("Startup-resync: panel returned %d", r.status_code)
                return
            data = r.json()
    except Exception as e:
        logger.warning("Startup-resync failed: %s", e)
        return

    clients = data.get("clients") or []
    rls = data.get("rate_limits") or []
    valid_entries = [(c["ip"], c["client_id"]) for c in clients if _valid_ip(c.get("ip", ""))]

    # Пересобрать ipset из payload
    _run(f"ipset create {IPSET_NAME} hash:ip maxelem 1000000 2>/dev/null")
    _run(f"ipset flush {IPSET_NAME}")
    unique_ips = set(ip for ip, _ in valid_entries)
    for ip in unique_ips:
        _run(f"ipset add {IPSET_NAME} {ip}")
    refcount.set_all(valid_entries)
    _save_ipset_now()

    # Применить rate_limits
    for rl in rls:
        ip = rl.get("ip")
        if ip and _valid_ip(ip):
            rate_limits.set_limit(
                ip=ip,
                mbps=float(rl["mbps"]),
                expires_at=rl.get("expires_at"),
                client_id=rl.get("client_id"),
            )

    logger.info("Startup-resync done: %d clients, %d rate_limits", len(unique_ips), len(rls))


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
    global _persist_event
    _persist_event = asyncio.Event()
    asyncio.create_task(_ipset_persist_loop())
    asyncio.create_task(_traffic_collector_loop())
    asyncio.create_task(metrics_sampler.loop())
    asyncio.create_task(_rules_watchdog_loop())
    # Restore rate-limits сразу (без ожидания первого тика watchdog'а)
    try:
        result = await asyncio.to_thread(rate_limits.restore_all)
        if result["applied"]:
            logger.info("Rate-limits restored: %d", len(result["applied"]))
        if result["failed"]:
            logger.warning("Rate-limits failed: %s", result["failed"])
    except Exception as e:
        logger.error("Rate-limits restore error: %s", e)
    # Опциональный resync с панели — fire-and-forget
    asyncio.create_task(_startup_resync())


# ═══════════════════════════════════════
# STATUS FILES
# ═══════════════════════════════════════

def _load_update_status() -> dict | None:
    try:
        return json.loads(UPDATE_STATUS_FILE.read_text())
    except Exception:
        return None


def _save_update_status(status: dict):
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        UPDATE_STATUS_FILE.write_text(json.dumps(status, indent=2))
    except Exception as e:
        logger.error("Could not save update status: %s", e)


def _load_sync_status() -> dict | None:
    try:
        return json.loads(SYNC_STATUS_FILE.read_text())
    except Exception:
        return None


def _save_sync_status(status: dict):
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        SYNC_STATUS_FILE.write_text(json.dumps(status, indent=2))
    except Exception as e:
        logger.error("Could not save sync status: %s", e)


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

class RateLimitRequest(BaseModel):
    ip: str
    mbps: float
    expires_at: str | None = None       # ISO 8601 либо null = бессрочно
    client_id: int | None = None


# ═══════════════════════════════════════
# WHITELIST ENDPOINTS
# ═══════════════════════════════════════

@app.post("/whitelist/update")
async def whitelist_update(data: IPUpdateRequest):
    if not _valid_ip(data.new_ip):
        raise HTTPException(400, f"Invalid new_ip: {data.new_ip}")
    if data.old_ip and not _valid_ip(data.old_ip):
        raise HTTPException(400, f"Invalid old_ip: {data.old_ip}")
    removed = None
    if data.client_id is not None:
        can_remove = refcount.add(data.new_ip, data.client_id, data.old_ip)
        if data.old_ip and can_remove:
            _run(f"ipset del {IPSET_NAME} {data.old_ip} 2>/dev/null")
            _run(f"conntrack -D -p udp -s {data.old_ip} 2>/dev/null")
            removed = data.old_ip
        elif data.old_ip and not can_remove:
            logger.info("Keeping %s in ipset (refcount=%d)", data.old_ip, refcount.count(data.old_ip))
    else:
        if data.old_ip:
            _run(f"ipset del {IPSET_NAME} {data.old_ip} 2>/dev/null")
            _run(f"conntrack -D -p udp -s {data.old_ip} 2>/dev/null")
            removed = data.old_ip
    _run(f"ipset add {IPSET_NAME} {data.new_ip} 2>/dev/null")
    _trigger_persist()
    return {
        "added": data.new_ip, "removed": removed,
        "client_id": data.client_id, "refcount": refcount.count(data.new_ip),
    }


@app.post("/whitelist/remove")
async def whitelist_remove(data: IPRequest):
    if not _valid_ip(data.ip):
        raise HTTPException(400, f"Invalid ip: {data.ip}")
    can_remove = refcount.remove_client(data.ip)
    if can_remove:
        _run(f"ipset del {IPSET_NAME} {data.ip} 2>/dev/null")
        _run(f"conntrack -D -p udp -s {data.ip} 2>/dev/null")
        _trigger_persist()
        return {"removed": data.ip}
    else:
        rc = refcount.count(data.ip)
        logger.info("Keeping %s in ipset (refcount=%d)", data.ip, rc)
        return {"removed": None, "kept": data.ip, "refcount": rc}


# ── Фоновая синхронизация ──

def _do_sync_sync(entries: list[dict]):
    """Синхронная работа с ipset в отдельном потоке."""
    started_at = _now_msk().isoformat()
    _save_sync_status({
        "ok": None,
        "in_progress": True,
        "total": len(entries),
        "started_at": started_at,
        "finished_at": None,
    })

    try:
        valid = [e for e in entries if _valid_ip(e["ip"])]
        invalid = [e["ip"] for e in entries if not _valid_ip(e["ip"])]

        _run(f"ipset create {IPSET_NAME} hash:ip maxelem 1000000 2>/dev/null")
        _run(f"ipset flush {IPSET_NAME}", check=True)

        unique_ips = set()
        rc_entries = []
        for entry in valid:
            unique_ips.add(entry["ip"])
            rc_entries.append((entry["ip"], entry["client_id"]))

        for ip in unique_ips:
            _run(f"ipset add {IPSET_NAME} {ip}")

        refcount.set_all(rc_entries)
        _save_ipset_now()

        _save_sync_status({
            "ok": True,
            "in_progress": False,
            "synced": len(unique_ips),
            "clients": len(valid),
            "invalid": len(invalid),
            "started_at": started_at,
            "finished_at": _now_msk().isoformat(),
        })
        logger.info("Sync complete: %d IPs, %d clients, %d invalid",
                    len(unique_ips), len(valid), len(invalid))

    except Exception as e:
        logger.error("Sync failed: %s", e)
        _save_sync_status({
            "ok": False,
            "in_progress": False,
            "error": str(e),
            "started_at": started_at,
            "finished_at": _now_msk().isoformat(),
        })


@app.post("/whitelist/sync")
async def whitelist_sync(data: SyncRequest):
    """Fire-and-forget: принимаем данные, обрабатываем в фоне."""
    entries = [{"ip": e.ip, "client_id": e.client_id} for e in data.clients]
    total = len(entries)

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _do_sync_sync, entries)

    return {
        "accepted": True,
        "received": total,
        "message": "Sync started in background",
        "check_status": "GET /health → last_sync",
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
# RATE-LIMIT ENDPOINTS
# ═══════════════════════════════════════

@app.post("/rate-limit")
async def rate_limit_set(data: RateLimitRequest):
    if not _valid_ip(data.ip):
        raise HTTPException(400, f"Invalid ip: {data.ip}")
    if data.mbps <= 0:
        raise HTTPException(400, "mbps must be > 0")
    result = rate_limits.set_limit(
        ip=data.ip, mbps=data.mbps,
        expires_at=data.expires_at, client_id=data.client_id,
    )
    if not result.get("ok"):
        raise HTTPException(500, result.get("error", "apply_failed"))
    return result


@app.delete("/rate-limit/{ip}")
async def rate_limit_remove(ip: str):
    if not _valid_ip(ip):
        raise HTTPException(400, f"Invalid ip: {ip}")
    result = rate_limits.remove_limit(ip)
    if not result.get("ok"):
        raise HTTPException(404, "not_found")
    return result


@app.get("/rate-limit/{ip}")
async def rate_limit_get(ip: str):
    if not _valid_ip(ip):
        raise HTTPException(400, f"Invalid ip: {ip}")
    info = rate_limits.get(ip)
    if not info:
        return {"ip": ip, "limited": False}
    return {"limited": True, **info}


@app.get("/rate-limits")
async def rate_limits_list():
    return {"items": rate_limits.all(), "count": len(rate_limits._map)}


# ═══════════════════════════════════════
# TRAFFIC ENDPOINTS
# ═══════════════════════════════════════

@app.get("/traffic")
async def traffic_all():
    return traffic_monitor.get_all()

@app.get("/traffic/{ip}")
async def traffic_by_ip(ip: str):
    if not _valid_ip(ip):
        raise HTTPException(400, f"Invalid IP: {ip}")
    result = traffic_monitor.get_ip(ip)
    if not result:
        return {
            "ip": ip, "month": traffic_monitor.traffic["month"],
            "tx_bytes": 0, "rx_bytes": 0, "total_bytes": 0,
            "tx_human": "0 B", "rx_human": "0 B", "total_human": "0 B",
            "clients_on_ip": refcount.count(ip),
            "client_ids": sorted(refcount._map.get(ip, set())),
            "updated": None,
        }
    return result

@app.post("/traffic/reset")
async def traffic_reset():
    traffic_monitor.reset()
    return {"ok": True, "month": traffic_monitor.traffic["month"]}


@app.get("/refcount")
async def refcount_list():
    return refcount.get_all()


# ═══════════════════════════════════════
# SELF-UPDATE
# ═══════════════════════════════════════

def _do_update_sync():
    repo = str(REPO_DIR)
    install = str(DATA_DIR)
    agent_src = f"{repo}/relay-agent"
    started_at = _now_msk().isoformat()

    try:
        lock_file = REPO_DIR / ".git" / "index.lock"
        if lock_file.exists():
            lock_file.unlink()
            logger.warning("Removed stale git lock: %s", lock_file)

        code, stdout, stderr = _run_killgroup(
            f"cd {repo} && git pull --ff-only 2>&1", timeout=30,
        )
        if code != 0 and "Timed out" not in stderr:
            code, stdout, stderr = _run_killgroup(
                f"cd {repo} && git pull 2>&1", timeout=30,
            )
        if code != 0:
            _save_update_status({
                "ok": False, "error": "git pull failed",
                "details": (stdout or stderr)[:500],
                "started_at": started_at,
                "finished_at": _now_msk().isoformat(),
            })
            logger.error("Update failed: git pull: %s", stdout or stderr)
            return

        no_changes = "Already up to date" in stdout or "Already up-to-date" in stdout

        if no_changes:
            _save_update_status({
                "ok": True, "no_changes": True,
                "version": AGENT_VERSION,
                "started_at": started_at,
                "finished_at": _now_msk().isoformat(),
            })
            logger.info("No updates available")
            return

        steps = [{"git_pull": "updated"}]

        new_version = AGENT_VERSION
        try:
            content = Path(f"{agent_src}/agent.py").read_text()
            for line in content.split("\n"):
                if "AGENT_VERSION" in line and "=" in line and not line.strip().startswith("#"):
                    new_version = line.split("=")[1].strip().strip('"').strip("'")
                    break
        except Exception:
            pass

        files_copied = []
        for fname in ["agent.py", "ensure_rules.sh"]:
            src = Path(f"{agent_src}/{fname}")
            dst = Path(f"{install}/{fname}")
            if src.exists():
                try:
                    _run(f"cp {src} {dst}")
                    if fname.endswith(".sh"):
                        _run(f"chmod +x {dst}")
                    files_copied.append(fname)
                except Exception as e:
                    steps.append({"copy_error": f"{fname}: {e}"})
        steps.append({"files_copied": files_copied})

        req_src = Path(f"{agent_src}/requirements.txt")
        req_dst = Path(f"{install}/requirements.txt")
        deps_updated = False
        if req_src.exists():
            try:
                src_content = req_src.read_text()
                dst_content = req_dst.read_text() if req_dst.exists() else ""
                if src_content != dst_content:
                    _run(f"cp {req_src} {req_dst}")
                    _run(f"{install}/venv/bin/pip install -q -r {req_dst}", timeout=60)
                    deps_updated = True
            except Exception as e:
                steps.append({"deps_error": str(e)})
        steps.append({"deps_updated": deps_updated})

        _save_update_status({
            "ok": True,
            "old_version": AGENT_VERSION,
            "new_version": new_version,
            "steps": steps,
            "started_at": started_at,
            "finished_at": _now_msk().isoformat(),
        })

        logger.info("Update complete: %s → %s, restarting...", AGENT_VERSION, new_version)

        subprocess.Popen(
            ["bash", "-c", "sleep 2 && systemctl restart warp-relay-agent"],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    except Exception as e:
        logger.error("Update failed: %s", e)
        _save_update_status({
            "ok": False, "error": str(e),
            "started_at": started_at,
            "finished_at": _now_msk().isoformat(),
        })


@app.post("/update")
async def self_update():
    if not (REPO_DIR / ".git").exists():
        return {
            "accepted": False,
            "error": f"Git repo not found at {REPO_DIR}",
            "hint": "Install via: git clone <repo> /opt/warp-relay-panel",
        }
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _do_update_sync)
    return {
        "accepted": True,
        "message": "Update started in background",
        "check_status": "GET /health → last_update",
    }


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
    load_val = "0"
    try:
        load_val = Path("/proc/loadavg").read_text().strip().split()[0]
    except Exception:
        pass
    mem_total = mem_available = 0
    try:
        with open("/proc/meminfo") as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                meminfo[parts[0].rstrip(":")] = int(parts[1])
            mem_total = meminfo.get("MemTotal", 0)
            mem_available = meminfo.get("MemAvailable", 0)
    except Exception:
        pass
    mem_used = mem_total - mem_available

    t = traffic_monitor.get_all()
    online = _get_online_clients()
    update_status = _load_update_status()
    sync_status = _load_sync_status()
    self_heal = _load_self_heal_status()
    metrics = metrics_sampler.snapshot()

    return {
        "status": "ok",
        "version": AGENT_VERSION,
        "uptime_seconds": int(time.time() - _START_TIME),
        "ip_forward": fwd == "1",
        "ipset_count": ipset_count,
        "online_clients": online["count"],
        "conntrack": f"{ct_cur}/{ct_max}",
        "load": float(load_val),
        "memory_mb": {"used": round(mem_used / 1024), "total": round(mem_total / 1024)},
        "cpu_percent_total": metrics["cpu_percent_total"],
        "cpu_percent_per_core": metrics["cpu_percent_per_core"],
        "cpu_count": metrics["cpu_count"],
        "agent_process": metrics["agent_process"],
        "network_speed": metrics["network_speed"],
        "disk": metrics_sampler.disk_snapshot(),
        "rate_limits_count": len(rate_limits._map),
        "traffic_month": t["month"],
        "traffic_total": t["total"],
        "traffic_ips": t["ip_count"],
        "last_update": update_status,
        "last_sync": sync_status,
        "last_self_heal": self_heal,
    }


@app.get("/stats")
async def stats():
    online = _get_online_clients()

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
        "online": online,
        "sessions": {"assured": assured, "unreplied": unreplied},
        "top_ports": top_ports,
        "network": speed,
        "traffic": traffic_monitor.get_all(),
    }


# ═══════════════════════════════════════
# RUN
# ═══════════════════════════════════════

if __name__ == "__main__":
    print(f"WARP Relay Agent v{AGENT_VERSION} starting on :{AGENT_PORT}")
    print(f"ipset: {IPSET_NAME}")
    print(f"Traffic: every {TRAFFIC_INTERVAL}s → {TRAFFIC_FILE}")
    print(f"Watchdog: every {RULES_WATCHDOG_INTERVAL}s")
    print(f"Repo: {REPO_DIR}")
    uvicorn.run(app, host="0.0.0.0", port=AGENT_PORT, log_level="info")
