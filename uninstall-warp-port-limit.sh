#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE="warp-port-limit.service"
UNIT="/etc/systemd/system/$SERVICE"
CONFIG="/etc/default/warp-port-limit"

[[ "$EUID" -eq 0 ]] || { echo "Run as root"; exit 1; }

PORT=""
if [[ -f "$CONFIG" ]]; then
    PORT="$(sed -nE 's/^PORT=([0-9]+)$/\1/p' "$CONFIG" | head -n 1)"
fi

if systemctl is-active --quiet "$SERVICE"; then
    systemctl disable --now "$SERVICE"
else
    systemctl disable "$SERVICE" 2>/dev/null || true
    if [[ -n "$PORT" && -x /usr/local/sbin/warp-port-unlimit ]]; then
        /usr/local/sbin/warp-port-unlimit "$PORT" || true
    fi
fi

rm -f "$UNIT" "$CONFIG"
rm -f /usr/local/sbin/warp-port-limit /usr/local/sbin/warp-port-unlimit
systemctl daemon-reload
systemctl reset-failed "$SERVICE" 2>/dev/null || true

echo "Persistent WARP port limit removed"
