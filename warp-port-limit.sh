#!/usr/bin/env bash
set -Eeuo pipefail

PORT="${1:?Usage: $0 PORT MBPS}"
MBPS="${2:?Usage: $0 PORT MBPS}"
RECIPE="${RECIPE:-/opt/warp-relay-agent/rules_recipe.json}"
MARK="0xfffe"
CLASS="1:fffe"

[[ "$EUID" -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "Invalid port"; exit 1; }
PORT=$((10#$PORT))
(( PORT >= 1 && PORT <= 65535 )) || { echo "Invalid port"; exit 1; }
[[ "$MBPS" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "Invalid Mbps"; exit 1; }
awk -v rate="$MBPS" 'BEGIN { exit !(rate > 0) }' || {
    echo "Mbps must be greater than zero"
    exit 1
}

[[ -f "$RECIPE" ]] || { echo "Recipe not found: $RECIPE"; exit 1; }

DST_IP="$(jq -r '.dst_ip // empty' "$RECIPE")"
IFACE="$(jq -r '.iface // empty' "$RECIPE")"
[[ -n "$IFACE" ]] || IFACE="$(ip route | awk '/default/ {print $5; exit}')"

jq -e --argjson port "$PORT" '.ports | index($port) != null' \
    "$RECIPE" >/dev/null || {
    echo "Port $PORT is not configured as a WARP relay port"
    exit 1
}

tc qdisc show dev "$IFACE" | grep -q 'qdisc htb 1:' || {
    echo "HTB qdisc 1: not found on $IFACE"
    exit 1
}

iptables -t mangle -S POSTROUTING |
    grep -q 'CONNMARK --restore-mark' || {
    echo "Agent CONNMARK rule not found"
    exit 1
}

TAG="WR_PORT_LIMIT_${PORT}"
OTHER="$(
    iptables -t mangle -S POSTROUTING |
        grep -oE 'WR_PORT_LIMIT_[0-9]+' |
        sort -u |
        grep -vx "$TAG" || true
)"

[[ -z "$OTHER" ]] || {
    echo "Another port limit is active: $OTHER"
    exit 1
}

UP=(-p udp -d "$DST_IP" --dport "$PORT" -m comment --comment "$TAG" -j MARK --set-xmark "$MARK/0xffffffff")
DOWN=(-p udp -s "$DST_IP" --sport "$PORT" -m comment --comment "$TAG" -j MARK --set-xmark "$MARK/0xffffffff")

tc class replace dev "$IFACE" parent 1: classid "$CLASS" \
    htb rate "${MBPS}mbit" ceil "${MBPS}mbit" burst 16k

tc filter replace dev "$IFACE" parent 1:0 protocol ip prio 2 \
    handle "$MARK" fw classid "$CLASS"

while iptables -t mangle -C POSTROUTING "${UP[@]}" 2>/dev/null; do
    iptables -t mangle -D POSTROUTING "${UP[@]}"
done

while iptables -t mangle -C POSTROUTING "${DOWN[@]}" 2>/dev/null; do
    iptables -t mangle -D POSTROUTING "${DOWN[@]}"
done

iptables -t mangle -A POSTROUTING "${UP[@]}"
iptables -t mangle -A POSTROUTING "${DOWN[@]}"

echo "WARP port $PORT limited to $MBPS Mbps on $IFACE"
