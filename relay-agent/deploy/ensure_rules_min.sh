#!/bin/bash
# ═══════════════════════════════════════
# WARP Relay (MIN) — pre-flight self-heal
# Запускается перед стартом агента (ExecStartPre) и периодически из watchdog'а.
#
# В отличие от full-варианта: НЕТ ipset-восстановления, FORWARD-правила
# простые ACCEPT (без --match-set whitelist).
# ═══════════════════════════════════════

TAG="WR_RULE"
RECIPE="${RECIPE:-/opt/warp-relay-agent/rules_recipe.json}"

G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'

# ── iptables NAT (WR_RULE) ──
rebuild_from_recipe() {
    if [ ! -f "$RECIPE" ]; then
        echo -e "${R}[ensure-min] Recipe $RECIPE не найден — нечего пересобирать${N}"
        return 1
    fi
    if ! command -v jq &>/dev/null; then
        echo -e "${R}[ensure-min] jq не установлен${N}"
        return 1
    fi

    SRC_IP=$(jq -r '.src_ip' "$RECIPE")
    DST_IP=$(jq -r '.dst_ip' "$RECIPE")
    PORTS=$(jq -r '.ports | join(",")' "$RECIPE")

    if [ -z "$SRC_IP" ] || [ -z "$DST_IP" ] || [ -z "$PORTS" ]; then
        echo -e "${R}[ensure-min] Recipe неполный${N}"
        return 1
    fi

    echo -e "${Y}[ensure-min] Пересобираем NAT+FORWARD из recipe${N}"

    iptables -t nat -S 2>/dev/null | grep "$TAG" | sed 's/^-A/-D/' | while read rule; do
        iptables -t nat $rule 2>/dev/null || true
    done
    iptables -S 2>/dev/null | grep -E "WR_FORWARD|WR_WHITELIST" | sed 's/^-A/-D/' | while read rule; do
        iptables $rule 2>/dev/null || true
    done

    IFS=',' read -ra PORT_ARR <<< "$PORTS"
    CHUNK_SIZE=15
    for ((i=0; i<${#PORT_ARR[@]}; i+=CHUNK_SIZE)); do
        CHUNK=("${PORT_ARR[@]:i:CHUNK_SIZE}")
        GROUP=$(IFS=,; echo "${CHUNK[*]}")

        iptables -t nat -A PREROUTING -d "$SRC_IP" -p udp \
            -m multiport --dports "$GROUP" \
            -j DNAT --to-destination "$DST_IP" \
            -m comment --comment "$TAG" 2>/dev/null

        iptables -t nat -A POSTROUTING -p udp -d "$DST_IP" \
            -m multiport --dports "$GROUP" \
            -j MASQUERADE \
            -m comment --comment "$TAG" 2>/dev/null

        iptables -A FORWARD -p udp -d "$DST_IP" \
            -m multiport --dports "$GROUP" \
            -j ACCEPT \
            -m comment --comment "WR_FORWARD_OUT" 2>/dev/null
        iptables -A FORWARD -p udp -s "$DST_IP" \
            -m multiport --sports "$GROUP" \
            -j ACCEPT \
            -m comment --comment "WR_FORWARD_IN" 2>/dev/null
    done

    netfilter-persistent save 2>/dev/null || true
    echo -e "${G}[ensure-min] NAT+FORWARD пересобран${N}"
    return 0
}

# ── iptables NAT ──
if ! iptables -t nat -S 2>/dev/null | grep -q "$TAG"; then
    echo -e "${Y}[ensure-min] iptables NAT не найдены${N}"
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent reload 2>/dev/null
    fi
    if ! iptables -t nat -S 2>/dev/null | grep -q "$TAG"; then
        rebuild_from_recipe || \
          echo -e "${R}[ensure-min] Запустите setup.sh для полной настройки${N}"
    fi
else
    echo "[ensure-min] iptables NAT OK"
fi

# ── iptables FORWARD ACCEPT ──
if ! iptables -S FORWARD 2>/dev/null | grep -q "WR_FORWARD_OUT"; then
    echo -e "${Y}[ensure-min] FORWARD ACCEPT правила потеряны — пересобираем${N}"
    rebuild_from_recipe || true
fi

# ── ip_forward ──
FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
if [ "$FWD" != "1" ]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
fi

# ── tc HTB qdisc + CONNMARK restore (для shared rate-limit) ──
IFACE=$(ip route | awk '/default/ {print $5; exit}')
if [ -n "$IFACE" ]; then
    if ! tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "qdisc htb 1:"; then
        echo -e "${Y}[ensure-min] HTB qdisc на $IFACE не найден — создаём${N}"
        tc qdisc add dev "$IFACE" root handle 1: htb default 999 2>/dev/null
        tc class add dev "$IFACE" parent 1: classid 1:999 htb rate 1000mbit 2>/dev/null
    fi
    if ! iptables -t mangle -S POSTROUTING 2>/dev/null | grep -q "CONNMARK --restore-mark"; then
        iptables -t mangle -A POSTROUTING -j CONNMARK --restore-mark 2>/dev/null
    fi
fi

echo "[ensure-min] Done"
