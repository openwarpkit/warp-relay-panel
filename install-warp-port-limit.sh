#!/usr/bin/env bash
set -Eeuo pipefail

PORT="${1:?Usage: $0 PORT MBPS}"
MBPS="${2:?Usage: $0 PORT MBPS}"
BASE_URL="${BASE_URL:-https://raw.githubusercontent.com/openwarpkit/warp-relay-panel/warp-port-limit-scripts}"
RECIPE="${RECIPE:-/opt/warp-relay-agent/rules_recipe.json}"
SERVICE="warp-port-limit.service"

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
jq -e --argjson port "$PORT" '.ports | index($port) != null' \
    "$RECIPE" >/dev/null || {
    echo "Port $PORT is not configured as a WARP relay port"
    exit 1
}

for command_name in curl install systemctl; do
    command -v "$command_name" >/dev/null || {
        echo "Required command not found: $command_name"
        exit 1
    }
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL "$BASE_URL/warp-port-limit.sh" -o "$TMP_DIR/warp-port-limit"
curl -fsSL "$BASE_URL/warp-port-unlimit.sh" -o "$TMP_DIR/warp-port-unlimit"
bash -n "$TMP_DIR/warp-port-limit"
bash -n "$TMP_DIR/warp-port-unlimit"

if systemctl is-active --quiet "$SERVICE"; then
    systemctl stop "$SERVICE"
fi

install -m 0755 "$TMP_DIR/warp-port-limit" /usr/local/sbin/warp-port-limit
install -m 0755 "$TMP_DIR/warp-port-unlimit" /usr/local/sbin/warp-port-unlimit

printf 'PORT=%s\nMBPS=%s\n' "$PORT" "$MBPS" \
    > /etc/default/warp-port-limit
chmod 0644 /etc/default/warp-port-limit

cat > "/etc/systemd/system/$SERVICE" <<'UNIT'
[Unit]
Description=WARP relay UDP port bandwidth limit
Requires=warp-relay-agent.service
Wants=network-online.target
After=network-online.target warp-relay-agent.service
PartOf=warp-relay-agent.service

[Service]
Type=oneshot
EnvironmentFile=/etc/default/warp-port-limit
ExecStart=/usr/local/sbin/warp-port-limit ${PORT} ${MBPS}
ExecStop=/usr/local/sbin/warp-port-unlimit ${PORT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl start "$SERVICE"

echo "Persistent WARP port limit enabled: $PORT at $MBPS Mbps"
