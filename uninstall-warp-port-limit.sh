#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE="warp-port-limit.service"
COLLECTOR_SERVICE="warp-port-limit-ip-collector.service"
UNIT="/etc/systemd/system/$SERVICE"
COLLECTOR_UNIT="/etc/systemd/system/$COLLECTOR_SERVICE"
CONFIG="/etc/default/warp-port-limit"

[[ "$EUID" -eq 0 ]] || { echo "Run as root"; exit 1; }

PORT=""
if [[ -f "$CONFIG" ]]; then
    PORT="$(awk -F '=' '$1 == "PORT" { print $2; exit }' "$CONFIG")"
fi

if systemctl is-active --quiet "$COLLECTOR_SERVICE"; then
    systemctl disable --now "$COLLECTOR_SERVICE"
else
    systemctl disable "$COLLECTOR_SERVICE" 2>/dev/null || true
fi

if systemctl is-active --quiet "$SERVICE"; then
    systemctl disable --now "$SERVICE"
else
    systemctl disable "$SERVICE" 2>/dev/null || true
    if [[ -n "$PORT" && -x /usr/local/sbin/warp-port-unlimit ]]; then
        /usr/local/sbin/warp-port-unlimit "$PORT" || true
    fi
fi

rm -f "$UNIT" "$COLLECTOR_UNIT" "$CONFIG"
rm -f /usr/local/sbin/warp-port-limit /usr/local/sbin/warp-port-unlimit \
    /usr/local/sbin/warp-limited-port-ip-collector
systemctl daemon-reload
systemctl reset-failed "$SERVICE" 2>/dev/null || true
systemctl reset-failed "$COLLECTOR_SERVICE" 2>/dev/null || true

echo "Persistent WARP port limit removed"
echo "Collected IP files in /opt/warp-relay-agent were preserved"
