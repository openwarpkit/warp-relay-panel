from __future__ import annotations

import argparse
import concurrent.futures
import getpass
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import paramiko
except ImportError:
    paramiko = None


REMOTE_AUDIT = r'''set -u
D=/opt/warp-relay-agent
AGENT_PORT=7580
AGENT_SECRET=
if [ -r "$D/.env" ]; then
    set -a
    . "$D/.env"
    set +a
fi
AUDIT_SAMPLE_SECONDS=__SAMPLE_SECONDS__ AUDIT_JOURNAL_HOURS=__JOURNAL_HOURS__ python3 - <<'PY'
import json
import os
import re
import subprocess
import time
import urllib.request

D = "/opt/warp-relay-agent"

def run(args, shell=False):
    return subprocess.run(
        args,
        shell=shell,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout

def api(path):
    request = urllib.request.Request(
        "http://127.0.0.1:" + os.getenv("AGENT_PORT", "7580") + "/" + path,
        headers={"X-Agent-Key": os.getenv("AGENT_SECRET", "")},
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            return json.load(response)
    except Exception:
        return {}

def read_int(path):
    try:
        return int(open(path, encoding="ascii").read())
    except Exception:
        return 0

def cpu_counters():
    try:
        return [int(value) for value in open("/proc/stat", encoding="ascii").readline().split()[1:]]
    except Exception:
        return []

def net_counters(iface):
    base = "/sys/class/net/" + iface + "/statistics/"
    names = [
        "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
        "rx_dropped", "tx_dropped", "rx_errors", "tx_errors",
    ]
    return {name: read_int(base + name) for name in names}

def parse_tc(text):
    unit_scale = {"bit": 0.000001, "Kbit": 0.001, "Mbit": 1.0, "Gbit": 1000.0}
    classes = {}
    current = None
    for line in text.splitlines():
        match = re.search(
            r"^class htb 1:([0-9a-fA-F]+).*?rate\s+([0-9.]+)([KMG]?bit)",
            line,
        )
        if match:
            current = int(match.group(1), 16)
            classes[current] = {
                "mbps": float(match.group(2)) * unit_scale[match.group(3)],
                "bytes": 0,
                "packets": 0,
                "dropped": 0,
                "overlimits": 0,
            }
            continue
        if current is None:
            continue
        match = re.search(
            r"Sent\s+(\d+)\s+bytes\s+(\d+)\s+pkt\s+\(dropped\s+(\d+),\s+overlimits\s+(\d+)",
            line,
        )
        if match:
            classes[current].update(
                bytes=int(match.group(1)),
                packets=int(match.group(2)),
                dropped=int(match.group(3)),
                overlimits=int(match.group(4)),
            )
    return classes

def kernel_snapshot(dst_ip, ports, iface):
    conntrack = run(["conntrack", "-L", "-p", "udp", "-o", "extended"])
    nft_map_text = run(["nft", "list", "map", "ip", "warp_shaper", "ip2mark"])
    tc_text = run(["tc", "-s", "class", "show", "dev", iface])
    nft_map = {
        ip: int(mark, 16)
        for ip, mark in re.findall(
            r"(\d+(?:\.\d+){3})\s*:\s*(0x[0-9a-fA-F]+)", nft_map_text
        )
    }
    clients = {}
    flows = 0
    for line in conntrack.splitlines():
        sources = re.findall(r"\bsrc=([^ ]+)", line)
        destination_ports = re.findall(r"\bdport=(\d+)", line)
        if len(sources) < 2 or not destination_ports:
            continue
        if sources[1] != dst_ip or int(destination_ports[0]) not in ports:
            continue
        flows += 1
        ip = sources[0]
        mark_match = re.search(r"\bmark=(\d+)", line)
        mark = int(mark_match.group(1)) if mark_match else 0
        byte_values = [int(value) for value in re.findall(r"\bbytes=(\d+)", line)]
        entry = clients.setdefault(
            ip,
            {"flows": 0, "marks": set(), "orig_bytes": 0, "reply_bytes": 0},
        )
        entry["flows"] += 1
        entry["marks"].add(mark)
        if byte_values:
            entry["orig_bytes"] += byte_values[0]
        if len(byte_values) > 1:
            entry["reply_bytes"] += byte_values[1]
    for entry in clients.values():
        entry["marks"] = sorted(entry["marks"])
    return {
        "clients": clients,
        "flows": flows,
        "nft_map": nft_map,
        "tc_classes": parse_tc(tc_text),
        "captured_at": time.time(),
    }

def journal_summary(hours):
    text = run(
        [
            "journalctl", "-u", "warp-relay-agent", "--since",
            "-" + str(hours) + " hours", "--no-pager", "-o", "cat",
        ]
    )
    lower = text.lower()
    failures = 0
    for line in lower.splitlines():
        if "0 errors" in line or "failed=0" in line:
            continue
        if any(token in line for token in (" error", "failed", "panic", "fatal", "enobufs")):
            failures += 1
    ipset_permission = lower.count("ipset persist failed")
    self_sync_failed = lower.count("self-sync: fetch failed")
    ipset_swap_error = lower.count("ipset swap error")
    command_failed = lower.count("command failed -:")
    classified = ipset_permission + self_sync_failed + ipset_swap_error + command_failed
    return {
        "failures": failures,
        "other_failures": max(0, failures - classified),
        "ipset_persist_failed": ipset_permission,
        "self_sync_failed": self_sync_failed,
        "ipset_swap_error": ipset_swap_error,
        "command_failed": command_failed,
        "drift": lower.count("rate-limit drift") + lower.count("rate_limit_drift"),
        "restore_all": lower.count("restoreall"),
        "self_heal": lower.count("self-heal"),
    }

health = api("health")
stats = api("stats")
shaped = api("shaped")
limits = api("rate-limits")
kind = "min" if health.get("shared_limit") or shaped.get("idle_grace") is not None else "full"
control = shaped if kind == "min" else limits

try:
    recipe = json.load(open(D + "/rules_recipe.json", encoding="utf-8"))
except Exception:
    recipe = {}

dst_ip = str(recipe.get("dst_ip", ""))
ports = {int(value) for value in recipe.get("ports", [])}
iface = run("ip route show default | awk 'NR==1{print $5}'", shell=True).strip()

filter_rules = run(["iptables", "-w", "-S", "FORWARD"])
nat_rules = run(["iptables", "-w", "-t", "nat", "-S"])
mangle_rules = run(["iptables", "-w", "-t", "mangle", "-S", "POSTROUTING"])
nft_table = run(["nft", "list", "table", "ip", "warp_shaper"])
qdisc = run(["tc", "qdisc", "show", "dev", iface])
filters = run(["tc", "filter", "show", "dev", iface, "parent", "1:0"])

systemctl = run(
    [
        "systemctl", "show", "warp-relay-agent",
        "-p", "ActiveState", "-p", "NRestarts", "-p", "ExecMainStartTimestamp", "-p", "User",
    ]
)
service = {}
for line in systemctl.splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        service[key] = value
service_user = service.get("User") or "root"
ipset_rules_writable = subprocess.run(
    ["runuser", "-u", service_user, "--", "test", "-w", "/etc/ipset.rules"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
).returncode == 0

first_cpu = cpu_counters()
first_net = net_counters(iface)
first = kernel_snapshot(dst_ip, ports, iface)
sample_seconds = float(os.getenv("AUDIT_SAMPLE_SECONDS", "4"))
time.sleep(sample_seconds)
second = kernel_snapshot(dst_ip, ports, iface)
second_cpu = cpu_counters()
second_net = net_counters(iface)
elapsed = max(0.001, second["captured_at"] - first["captured_at"])

cpu = {}
if first_cpu and len(first_cpu) == len(second_cpu):
    delta = [end - start for start, end in zip(first_cpu, second_cpu)]
    total = sum(delta)
    names = ["user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal"]
    if total > 0:
        cpu = {name: round(100 * delta[index] / total, 2) for index, name in enumerate(names)}
        cpu["busy"] = round(100 * (total - delta[3] - delta[4]) / total, 2)

network_sample = {"seconds": elapsed}
for direction in ("rx", "tx"):
    byte_delta = second_net[direction + "_bytes"] - first_net[direction + "_bytes"]
    packet_delta = second_net[direction + "_packets"] - first_net[direction + "_packets"]
    network_sample[direction + "_mbps"] = round(8 * byte_delta / elapsed / 1_000_000, 2)
    network_sample[direction + "_kpps"] = round(packet_delta / elapsed / 1000, 2)
network_sample["drop_delta"] = sum(
    second_net[name] - first_net[name] for name in ("rx_dropped", "tx_dropped")
)
network_sample["error_delta"] = sum(
    second_net[name] - first_net[name] for name in ("rx_errors", "tx_errors")
)

traffic = stats.get("traffic", {})
traffic_ip_values = list((traffic.get("ips") or {}).values())
traffic_summary = {
    key: traffic.get(key)
    for key in (
        "month", "last_reset", "total_tx_bytes", "total_rx_bytes", "total_bytes",
        "total_tx", "total_rx", "total", "ip_count",
    )
}
traffic_summary.update(
    shared_ip_count=sum(int(item.get("clients_on_ip") or 0) > 1 for item in traffic_ip_values),
    unassigned_ip_count=sum(int(item.get("clients_on_ip") or 0) == 0 for item in traffic_ip_values),
    max_clients_on_ip=max((int(item.get("clients_on_ip") or 0) for item in traffic_ip_values), default=0),
)

output = {
    "kind": kind,
    "health": health,
    "stats": {
        "sessions": stats.get("sessions"),
        "network": stats.get("network"),
        "online_count": (stats.get("online") or {}).get("count"),
        "traffic": traffic_summary,
    },
    "control": control,
    "recipe": {"dst_ip": dst_ip, "port_count": len(ports), "iface": iface},
    "kernel": {"first": first, "second": second},
    "rules": {
        "qdisc_htb": "qdisc htb 1:" in qdisc,
        "flow_filter": "flow" in filters,
        "nft_mark_rule": "ct mark set ip saddr map @ip2mark" in nft_table,
        "restore_mark": "CONNMARK --restore-mark" in mangle_rules,
        "nat": "WR_RULE" in nat_rules,
        "min_forward_out": "WR_FORWARD_OUT" in filter_rules,
        "min_forward_in": "WR_FORWARD_IN" in filter_rules,
        "full_forward_out": "WR_WHITELIST_OUT" in filter_rules,
        "full_forward_in": "WR_WHITELIST_IN" in filter_rules,
        "full_drop": "WR_WHITELIST_DROP" in filter_rules,
    },
    "system": {
        "hostname": run(["hostname"]).strip(),
        "kernel": run(["uname", "-r"]).strip(),
        "service": service,
        "service_user": service_user,
        "ipset_rules_writable": ipset_rules_writable,
        "ip_forward": read_int("/proc/sys/net/ipv4/ip_forward"),
        "conntrack_count": read_int("/proc/sys/net/netfilter/nf_conntrack_count"),
        "conntrack_max": read_int("/proc/sys/net/netfilter/nf_conntrack_max"),
        "cpu": cpu,
        "network_sample": network_sample,
        "network_counters": second_net,
    },
    "journal": journal_summary(int(os.getenv("AUDIT_JOURNAL_HOURS", "24"))),
}
print(json.dumps(output, separators=(",", ":")))
PY
'''


@dataclass
class Finding:
    severity: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"severity": self.severity, "code": self.code, "message": self.message}


@dataclass
class ServerConfig:
    name: str
    host: str
    expected_type: str
    username: str = "root"
    port: int = 22
    password: str | None = field(default=None, repr=False)
    password_env: str | None = None
    key_filename: str | None = None
    expected_limit_mbps: float | None = None


def load_env_file(path: Path | None) -> None:
    if path is None:
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def load_inventory(path: Path, allow_prompt: bool) -> tuple[list[ServerConfig], dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    defaults = raw.get("defaults", {})
    servers = []
    for item in raw.get("servers", []):
        merged = {**defaults, **item}
        config = ServerConfig(
            name=merged["name"],
            host=merged["host"],
            expected_type=merged["type"],
            username=merged.get("username", "root"),
            port=int(merged.get("port", 22)),
            password=merged.get("password"),
            password_env=merged.get("password_env"),
            key_filename=merged.get("key_filename"),
            expected_limit_mbps=merged.get("expected_limit_mbps"),
        )
        if not config.password and config.password_env:
            config.password = os.getenv(config.password_env)
        if not config.password and not config.key_filename and allow_prompt:
            config.password = getpass.getpass(f"SSH password for {config.name} ({config.host}): ")
        servers.append(config)
    if not servers:
        raise ValueError("Inventory has no servers")
    return servers, raw


def ssh_collect(
    server: ServerConfig,
    sample_seconds: float,
    journal_hours: int,
    accept_new_host_keys: bool,
    connect_timeout: float,
) -> dict[str, Any]:
    if paramiko is None:
        raise RuntimeError("Paramiko is required: python -m pip install paramiko")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if accept_new_host_keys:
        client.set_missing_host_key_policy(paramiko.WarningPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    command = REMOTE_AUDIT.replace("__SAMPLE_SECONDS__", str(sample_seconds)).replace(
        "__JOURNAL_HOURS__", str(journal_hours)
    )
    try:
        client.connect(
            server.host,
            port=server.port,
            username=server.username,
            password=server.password,
            key_filename=server.key_filename,
            timeout=connect_timeout,
            auth_timeout=connect_timeout,
            banner_timeout=connect_timeout,
            look_for_keys=not bool(server.password),
            allow_agent=True,
        )
        stdin, stdout, stderr = client.exec_command("bash -s", timeout=max(60, sample_seconds + 45))
        stdin.write(command)
        stdin.channel.shutdown_write()
        output = stdout.read().decode("utf-8", errors="replace").strip()
        error = stderr.read().decode("utf-8", errors="replace").strip()
        status = stdout.channel.recv_exit_status()
        if status != 0 or not output:
            raise RuntimeError(f"remote audit failed ({status}): {error[-500:]}")
        data = json.loads(output)
        data["ssh_stderr"] = error[-500:]
        return data
    finally:
        client.close()


def ip_label(ip: str, include_client_ips: bool, salt: str) -> str:
    if include_client_ips:
        return ip
    digest = hashlib.sha256((salt + ip).encode()).hexdigest()[:10]
    return "ip#" + digest


def severity_rank(value: str) -> int:
    return {"pass": 0, "info": 0, "warn": 1, "fail": 2}.get(value, 2)


def add_missing_rule_findings(data: dict[str, Any], kind: str, findings: list[Finding]) -> None:
    required = ["qdisc_htb", "flow_filter", "nft_mark_rule", "restore_mark", "nat"]
    if kind == "min":
        required.extend(["min_forward_out", "min_forward_in"])
    else:
        required.extend(["full_forward_out", "full_forward_in", "full_drop"])
    missing = [name for name in required if not data.get("rules", {}).get(name)]
    if missing:
        findings.append(Finding("fail", "kernel_rules_missing", "Missing: " + ", ".join(missing)))


def assess_snapshot(
    snapshot: dict[str, Any],
    kind: str,
    expected: dict[str, dict[str, Any]],
    default_mbps: float,
) -> dict[str, set[str]]:
    active = snapshot.get("clients", {})
    nft_map = {ip: int(mark) for ip, mark in snapshot.get("nft_map", {}).items()}
    tc_classes = {int(mark): value for mark, value in snapshot.get("tc_classes", {}).items()}
    target = set(active) if kind == "min" else set(active) & set(expected)
    issue = {
        "zero_mark": set(),
        "map_mismatch": set(),
        "class_missing": set(),
        "rate_mismatch": set(),
        "flow_class_missing": set(),
        "effective_rate_mismatch": set(),
    }
    for ip in target:
        marks = {int(mark) for mark in active[ip].get("marks", [])}
        desired_mark = int(expected.get(ip, {}).get("mark", 0))
        desired_rate = float(expected.get(ip, {}).get("mbps") or default_mbps)
        if 0 in marks:
            issue["zero_mark"].add(ip)
        if nft_map.get(ip) != desired_mark:
            issue["map_mismatch"].add(ip)
        desired_class = tc_classes.get(desired_mark)
        if desired_class is None:
            issue["class_missing"].add(ip)
        elif abs(float(desired_class.get("mbps", 0)) - desired_rate) > 0.02:
            issue["rate_mismatch"].add(ip)
        for mark in marks - {0}:
            flow_class = tc_classes.get(mark)
            if flow_class is None:
                issue["flow_class_missing"].add(ip)
            elif abs(float(flow_class.get("mbps", 0)) - desired_rate) > 0.02:
                issue["effective_rate_mismatch"].add(ip)
    return issue


def summarize_server(
    server: ServerConfig,
    raw: dict[str, Any],
    include_client_ips: bool,
    salt: str,
) -> dict[str, Any]:
    findings: list[Finding] = []
    kind = raw.get("kind", "unknown")
    health = raw.get("health", {})
    control_items = raw.get("control", {}).get("items", []) or []
    default_mbps = float((health.get("shared_limit") or {}).get("mbps") or 0)
    expected = {}
    for item in control_items:
        ip = item.get("ip")
        if not ip:
            continue
        expected[ip] = {
            "mark": int(item.get("mark", 0)),
            "mbps": float(item.get("mbps") or default_mbps),
        }
    if kind != server.expected_type:
        findings.append(
            Finding("fail", "agent_type", f"Expected {server.expected_type}, detected {kind}")
        )
    if raw.get("system", {}).get("service", {}).get("ActiveState") != "active":
        findings.append(Finding("fail", "service", "warp-relay-agent is not active"))
    if raw.get("system", {}).get("ip_forward") != 1:
        findings.append(Finding("fail", "ip_forward", "net.ipv4.ip_forward is disabled"))
    add_missing_rule_findings(raw, kind, findings)

    if kind == "min":
        if server.expected_limit_mbps is not None and abs(default_mbps - server.expected_limit_mbps) > 0.02:
            findings.append(
                Finding(
                    "fail",
                    "shared_limit",
                    f"Configured {default_mbps:g} Mbps, expected {server.expected_limit_mbps:g} Mbps",
                )
            )
        if health.get("traffic_ips") == 0:
            findings.append(
                Finding("info", "aggregate_traffic", "MIN traffic mode is aggregate; per-user usage is unavailable")
            )

    first = raw.get("kernel", {}).get("first", {})
    second = raw.get("kernel", {}).get("second", {})
    first_issues = assess_snapshot(first, kind, expected, default_mbps)
    second_issues = assess_snapshot(second, kind, expected, default_mbps)
    persistent = {
        key: first_issues[key] & second_issues[key]
        for key in first_issues
    }

    critical_messages = {
        "zero_mark": "active limited clients retain conntrack mark 0",
        "flow_class_missing": "active marked flows have no HTB class",
        "effective_rate_mismatch": "active flows use an HTB class with the wrong rate",
    }
    for key, message in critical_messages.items():
        if persistent[key]:
            labels = [ip_label(ip, include_client_ips, salt) for ip in sorted(persistent[key])[:5]]
            findings.append(
                Finding("fail", key, f"{message}: {len(persistent[key])}; sample {', '.join(labels)}")
            )

    metadata_severity = "fail" if kind == "full" else "warn"
    metadata_messages = {
        "map_mismatch": "agent mark differs from nft map",
        "class_missing": "agent HTB class is missing",
        "rate_mismatch": "agent HTB class has the wrong rate",
    }
    for key, message in metadata_messages.items():
        if persistent[key]:
            labels = [ip_label(ip, include_client_ips, salt) for ip in sorted(persistent[key])[:5]]
            findings.append(
                Finding(
                    metadata_severity,
                    key,
                    f"{message}: {len(persistent[key])}; sample {', '.join(labels)}",
                )
            )

    second_nft = {ip: int(mark) for ip, mark in second.get("nft_map", {}).items()}
    second_tc = {int(mark): item for mark, item in second.get("tc_classes", {}).items()}
    expected_marks = {int(item["mark"]) for item in expected.values()}
    extra_nft = set(second_nft) - set(expected)
    extra_classes = set(second_tc) - expected_marks - {65535}
    if kind == "full" and extra_nft:
        findings.append(Finding("warn", "stale_nft", f"Extra nft entries: {len(extra_nft)}"))
    if kind == "full" and extra_classes:
        findings.append(Finding("warn", "stale_tc", f"Extra HTB classes: {len(extra_classes)}"))

    limited_classes = [second_tc.get(mark) for mark in expected_marks if second_tc.get(mark)]
    overlimit_classes = sum(1 for item in limited_classes if int(item.get("overlimits", 0)) > 0)
    overlimits = sum(int(item.get("overlimits", 0)) for item in limited_classes)
    drops = sum(int(item.get("dropped", 0)) for item in limited_classes)

    system = raw.get("system", {})
    cpu = system.get("cpu", {})
    network = system.get("network_sample", {})
    if float(cpu.get("steal", 0)) >= 10:
        findings.append(Finding("warn", "cpu_steal", f"CPU steal is {cpu.get('steal')}%"))
    if int(network.get("drop_delta", 0)) > 0:
        findings.append(
            Finding("warn", "network_drops", f"Interface drops during sample: {network.get('drop_delta')}")
        )
    count = int(system.get("conntrack_count", 0))
    maximum = int(system.get("conntrack_max", 0))
    conntrack_pct = round(100 * count / maximum, 2) if maximum else 0
    if conntrack_pct >= 80:
        findings.append(Finding("fail", "conntrack_capacity", f"Conntrack usage is {conntrack_pct}%"))

    journal = raw.get("journal", {})
    if kind == "full" and not system.get("ipset_rules_writable", False):
        findings.append(
            Finding(
                "warn",
                "ipset_persist_permission",
                "Agent service user cannot update /etc/ipset.rules; startup resync is required after reboot",
            )
        )
    if int(journal.get("self_sync_failed", 0)):
        findings.append(
            Finding(
                "warn",
                "panel_self_sync",
                f"Panel self-sync fetch failures: {journal.get('self_sync_failed')}",
            )
        )
    if int(journal.get("ipset_swap_error", 0)):
        findings.append(
            Finding(
                "warn",
                "ipset_swap",
                f"ipset swap errors: {journal.get('ipset_swap_error')}",
            )
        )
    if int(journal.get("command_failed", 0)):
        findings.append(
            Finding(
                "info",
                "command_failed",
                f"Unclassified command failures in journal: {journal.get('command_failed')}",
            )
        )
    if int(journal.get("other_failures", 0)):
        findings.append(
            Finding(
                "warn",
                "journal_failures",
                f"Relevant non-ipset journal failures: {journal.get('other_failures')}",
            )
        )

    traffic = raw.get("stats", {}).get("traffic", {})
    tx = int(traffic.get("total_tx_bytes") or 0)
    rx = int(traffic.get("total_rx_bytes") or 0)
    interface = raw.get("stats", {}).get("network", {}) or {}
    interface_tx = int(interface.get("tx_bytes_total") or 0)
    interface_rx = int(interface.get("rx_bytes_total") or 0)
    limit_fingerprint = hashlib.sha256(
        json.dumps(sorted((ip, item["mbps"]) for ip, item in expected.items()), separators=(",", ":")).encode()
    ).hexdigest()[:12]
    active = second.get("clients", {})
    active_limited = set(active) if kind == "min" else set(active) & set(expected)
    status = "pass"
    if findings:
        highest = max(severity_rank(item.severity) for item in findings)
        status = "fail" if highest == 2 else "warn" if highest == 1 else "pass"
    return {
        "name": server.name,
        "host": server.host,
        "expected_type": server.expected_type,
        "detected_type": kind,
        "status": status,
        "version": health.get("version"),
        "uptime_seconds": health.get("uptime_seconds"),
        "online_clients": health.get("online_clients"),
        "active_warp_clients": len(active),
        "active_limited_clients": len(active_limited),
        "active_warp_flows": second.get("flows", 0),
        "configured_limits": len(expected),
        "shared_limit_mbps": default_mbps if kind == "min" else None,
        "limit_fingerprint": limit_fingerprint,
        "kernel": {
            "nft_entries": len(second_nft),
            "tc_classes": len(second_tc),
            "overlimit_classes": overlimit_classes,
            "overlimits": overlimits,
            "drops": drops,
            "persistent_zero_mark": len(persistent["zero_mark"]),
            "persistent_map_mismatch": len(persistent["map_mismatch"]),
            "persistent_class_missing": len(persistent["class_missing"]),
            "persistent_rate_mismatch": len(persistent["rate_mismatch"]),
            "persistent_flow_class_missing": len(persistent["flow_class_missing"]),
            "persistent_effective_rate_mismatch": len(persistent["effective_rate_mismatch"]),
        },
        "resources": {
            "cpu": cpu,
            "network_sample": network,
            "memory_mb": health.get("memory_mb"),
            "disk": health.get("disk"),
            "conntrack_percent": conntrack_pct,
        },
        "traffic": {
            "month": traffic.get("month"),
            "tx_bytes": tx,
            "rx_bytes": rx,
            "tx_rx_ratio": round(tx / rx, 3) if rx else None,
            "ip_count": traffic.get("ip_count"),
            "shared_ip_count": traffic.get("shared_ip_count"),
            "unassigned_ip_count": traffic.get("unassigned_ip_count"),
            "max_clients_on_ip": traffic.get("max_clients_on_ip"),
            "interface_tx_bytes": interface_tx,
            "interface_rx_bytes": interface_rx,
            "interface_tx_rx_ratio": round(interface_tx / interface_rx, 4) if interface_rx else None,
        },
        "journal": journal,
        "findings": [item.as_dict() for item in findings],
    }


def format_bytes(value: int | None) -> str:
    number = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if number < 1024 or unit == "PB":
            return f"{number:.1f} {unit}"
        number /= 1024
    return f"{number:.1f} PB"


def build_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# WARP relay audit",
        "",
        f"Generated: {report['generated_at']}",
        f"Overall status: **{report['status'].upper()}**",
        "",
        "| Server | Type | Status | Active WARP | Limited | Kernel rate path | CPU / steal | Network |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for server in report["servers"]:
        resources = server.get("resources", {})
        cpu = resources.get("cpu", {})
        net = resources.get("network_sample", {})
        kernel = server.get("kernel", {})
        effective_broken = any(
            kernel.get(key, 0)
            for key in (
                "persistent_zero_mark",
                "persistent_flow_class_missing",
                "persistent_effective_rate_mismatch",
            )
        )
        metadata_drift = any(
            kernel.get(key, 0)
            for key in (
                "persistent_map_mismatch",
                "persistent_class_missing",
                "persistent_rate_mismatch",
            )
        )
        path = "BROKEN" if effective_broken else "OK (DRIFT)" if metadata_drift else "OK"
        lines.append(
            "| {name} | {kind} | {status} | {active} | {limited} | {path} | {busy}% / {steal}% | {rx}/{tx} Mbps |".format(
                name=server["name"],
                kind=server.get("detected_type", "?"),
                status=server["status"].upper(),
                active=server.get("active_warp_clients", 0),
                limited=server.get("configured_limits", 0),
                path=path,
                busy=cpu.get("busy", 0),
                steal=cpu.get("steal", 0),
                rx=net.get("rx_mbps", 0),
                tx=net.get("tx_mbps", 0),
            )
        )
    lines.extend(["", "## Findings", ""])
    any_findings = False
    for server in report["servers"]:
        if not server.get("findings"):
            continue
        any_findings = True
        lines.append(f"### {server['name']}")
        lines.append("")
        for finding in server["findings"]:
            lines.append(
                f"- **{finding['severity'].upper()}** `{finding['code']}`: {finding['message']}"
            )
        lines.append("")
    for finding in report.get("global_findings", []):
        any_findings = True
        lines.append(f"- **{finding['severity'].upper()}** `{finding['code']}`: {finding['message']}")
    if not any_findings:
        lines.append("No findings.")

    lines.extend(["", "## Traffic accounting", ""])
    for server in report["servers"]:
        traffic = server.get("traffic", {})
        lines.append(
            f"- {server['name']}: client TX {format_bytes(traffic.get('tx_bytes'))}, "
            f"client RX {format_bytes(traffic.get('rx_bytes'))}, "
            f"TX/RX {traffic.get('tx_rx_ratio')}; interface TX/RX {traffic.get('interface_tx_rx_ratio')}; "
            f"shared current IPs {traffic.get('shared_ip_count') or 0}."
        )
    lines.extend(
        [
            "",
            "Interface RX and TX are normally close on a one-interface relay: each forwarded byte enters and leaves the same interface. This is not duplicate client billing.",
            "",
            "Full-agent client traffic uses conntrack original/reply deltas. MIN aggregate mode uses interface counters and cannot attribute usage to individual clients.",
            "",
            "Full accounting is IP-based, not identity-based. Clients sharing a public IP see the same IP total, and traffic from an older client IP is not returned by the current-IP client endpoint.",
        ]
    )
    return "\n".join(lines) + "\n"


def audit(args: argparse.Namespace) -> dict[str, Any]:
    load_env_file(args.env_file)
    servers, _ = load_inventory(args.inventory, not args.no_prompt)
    salt = os.urandom(16).hex()
    collected: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    workers = min(args.workers, len(servers))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(
                ssh_collect,
                server,
                args.sample_seconds,
                args.journal_hours,
                args.accept_new_host_keys,
                args.connect_timeout,
            ): server
            for server in servers
        }
        for future in concurrent.futures.as_completed(future_map):
            server = future_map[future]
            try:
                collected[server.name] = future.result()
            except Exception as exc:
                errors[server.name] = f"{type(exc).__name__}: {exc}"

    summaries = []
    for server in servers:
        if server.name in errors:
            summaries.append(
                {
                    "name": server.name,
                    "host": server.host,
                    "expected_type": server.expected_type,
                    "status": "fail",
                    "findings": [
                        Finding("fail", "ssh", errors[server.name]).as_dict()
                    ],
                }
            )
            continue
        summaries.append(
            summarize_server(server, collected[server.name], args.include_client_ips, salt)
        )

    global_findings = []
    full = [server for server in summaries if server.get("detected_type") == "full"]
    fingerprints = {server.get("limit_fingerprint") for server in full}
    counts = {server.get("configured_limits") for server in full}
    if len(fingerprints) > 1 or len(counts) > 1:
        global_findings.append(
            Finding("fail", "full_limit_sync", "Full relays have different rate-limit sets").as_dict()
        )
    elif full:
        global_findings.append(
            Finding(
                "info",
                "full_limit_sync",
                f"All {len(full)} full relays have the same {next(iter(counts))} rate limits",
            ).as_dict()
        )

    severities = [
        severity_rank(finding["severity"])
        for server in summaries
        for finding in server.get("findings", [])
    ] + [severity_rank(finding["severity"]) for finding in global_findings]
    highest = max(severities, default=0)
    status = "fail" if highest == 2 else "warn" if highest == 1 else "pass"
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "servers": summaries,
        "global_findings": global_findings,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit WARP relay agents over SSH")
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--sample-seconds", type=float, default=4.0)
    parser.add_argument("--journal-hours", type=int, default=24)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--connect-timeout", type=float, default=15.0)
    parser.add_argument("--accept-new-host-keys", action="store_true")
    parser.add_argument("--include-client-ips", action="store_true")
    parser.add_argument("--no-prompt", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = audit(args)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = args.output_dir / f"relay-audit-{stamp}.json"
    markdown_path = args.output_dir / f"relay-audit-{stamp}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown = build_markdown(report)
    markdown_path.write_text(markdown, encoding="utf-8")
    print(markdown)
    print(f"JSON: {json_path}", file=sys.stderr)
    print(f"Markdown: {markdown_path}", file=sys.stderr)
    return 2 if report["status"] == "fail" else 1 if report["status"] == "warn" else 0


if __name__ == "__main__":
    raise SystemExit(main())
