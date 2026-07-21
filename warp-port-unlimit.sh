#!/usr/bin/env bash
set -Eeuo pipefail

PORT="${1:?Usage: $0 PORT}"
RECIPE="${RECIPE:-/opt/warp-relay-agent/rules_recipe.json}"
MARK="0xfffe"
CLASS="1:fffe"

[[ "$EUID" -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "Invalid port"; exit 1; }
PORT=$((10#$PORT))
(( PORT >= 1 && PORT <= 65535 )) || { echo "Invalid port"; exit 1; }
[[ -f "$RECIPE" ]] || { echo "Recipe not found: $RECIPE"; exit 1; }

DST_IP="$(jq -r '.dst_ip // empty' "$RECIPE")"
IFACE="$(jq -r '.iface // empty' "$RECIPE")"
[[ -n "$IFACE" ]] || IFACE="$(ip route | awk '/default/ {print $5; exit}')"

TAG="WR_PORT_LIMIT_${PORT}"
UP=(-p udp -d "$DST_IP" --dport "$PORT" -m comment --comment "$TAG" -j MARK --set-xmark "$MARK/0xffffffff")
DOWN=(-p udp -s "$DST_IP" --sport "$PORT" -m comment --comment "$TAG" -j MARK --set-xmark "$MARK/0xffffffff")
FOUND=0

while iptables -t mangle -C POSTROUTING "${UP[@]}" 2>/dev/null; do
    iptables -t mangle -D POSTROUTING "${UP[@]}"
    FOUND=1
done

while iptables -t mangle -C POSTROUTING "${DOWN[@]}" 2>/dev/null; do
    iptables -t mangle -D POSTROUTING "${DOWN[@]}"
    FOUND=1
done

if (( FOUND == 0 )); then
    echo "No active limit found for WARP port $PORT"
    exit 0
fi

tc filter del dev "$IFACE" parent 1:0 protocol ip prio 2 \
    handle "$MARK" fw 2>/dev/null || true

tc class del dev "$IFACE" classid "$CLASS" 2>/dev/null || true

echo "Limit removed from WARP port $PORT"
