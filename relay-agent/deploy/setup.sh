#!/bin/bash
# ═══════════════════════════════════════
# WARP Relay (Go, full) - setup
# Run: sudo bash setup.sh
#
# Downloads fresh binary from GitHub Releases (no build on VPS).
# Configures iptables/ipset/tc, systemd, restore on reboot.
# ═══════════════════════════════════════

set -e

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'; B='\033[1m'

echo -e "${B}═══════════════════════════════════════${N}"
echo -e "${B}  WARP Relay (Go, full) — Setup${N}"
echo -e "${B}═══════════════════════════════════════${N}"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${R}Run as root: sudo bash $0${N}"
    exit 1
fi

read -p "Agent secret (shared with panel): " AGENT_SECRET
read -p "Agent port [7580]: " AGENT_PORT
AGENT_PORT=${AGENT_PORT:-7580}

INSTALL_DIR="/opt/warp-relay-agent"
TAG="WR_RULE"
BIN_NAME="warp-relay-agent"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GO_AGENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"   # …/relay-agent
REPO_DIR="$(cd "${GO_AGENT_DIR}/.." && pwd)"     # …/warp-relay-panel

# owner/repo for downloading binaries. Override: AGENT_RELEASE_REPO=user/repo
RELEASE_REPO="${AGENT_RELEASE_REPO:-nellimonix/warp-relay-panel}"

# ═══════════════════════════════════════
# 1. PACKAGES
# ═══════════════════════════════════════

echo -e "${Y}[1/7] Installing packages...${N}"
export DEBIAN_FRONTEND=noninteractive
apt update -qq
# nftables is needed for O(1) per-IP CONNMARK via map @ip2mark (v2.2.1+)
apt install -y -qq iptables nftables ipset curl conntrack netfilter-persistent ipset-persistent git jq iproute2

# ═══════════════════════════════════════
# 2. SYSTEM
# ═══════════════════════════════════════

echo -e "${Y}[2/7] Configuring system...${N}"
timedatectl set-timezone Europe/Moscow 2>/dev/null || ln -sf /usr/share/zoneinfo/Europe/Moscow /etc/localtime
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/ipv4-forwarding.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.netfilter.nf_conntrack_acct=1" > /etc/sysctl.d/conntrack-acct.conf
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true

# ═══════════════════════════════════════
# 3. IPSET
# ═══════════════════════════════════════

echo -e "${Y}[3/7] ipset...${N}"
if ! ipset list warp_whitelist &>/dev/null; then
    ipset create warp_whitelist hash:ip maxelem 1000000
fi

# ═══════════════════════════════════════
# 4. IPTABLES + RECIPE
# ═══════════════════════════════════════

echo -e "${Y}[4/7] iptables NAT/FORWARD...${N}"
SRC_IP=$(curl -4s ifconfig.me)
DST_IP=$(getent ahostsv4 engage.cloudflareclient.com | awk '{print $1; exit}')
echo -e "  Relay IP: ${B}${SRC_IP}${N}, CF IP: ${B}${DST_IP}${N}"

iptables -t nat -S | grep "WR_RULE" | sed 's/^-A/-D/' | while read rule; do
    iptables -t nat $rule 2>/dev/null || true
done
iptables -S | grep "WR_RULE\|WR_WHITELIST" | sed 's/^-A/-D/' | while read rule; do
    iptables $rule 2>/dev/null || true
done

PORTS=(500 854 859 864 878 880 890 891 894 903 908 928 934 939 942 943 945 946 955 968 987 988 1002 1010 1014 1018 1070 1074 1180 1387 1701 1843 2371 2408 2506 3138 3476 3581 3854 4177 4198 4233 4500 5279 5956 7103 7152 7156 7281 7559 8319 8742 8854 8886)
CHUNK_SIZE=15
for ((i=0; i<${#PORTS[@]}; i+=CHUNK_SIZE)); do
    CHUNK=("${PORTS[@]:i:CHUNK_SIZE}")
    GROUP=$(IFS=,; echo "${CHUNK[*]}")
    iptables -t nat -A PREROUTING -d ${SRC_IP} -p udp -m multiport --dports ${GROUP} \
        -j DNAT --to-destination ${DST_IP} -m comment --comment "${TAG}"
    iptables -t nat -A POSTROUTING -p udp -d ${DST_IP} -m multiport --dports ${GROUP} \
        -j MASQUERADE -m comment --comment "${TAG}"
done

iptables -I FORWARD 1 -p udp -d ${DST_IP} -m set --match-set warp_whitelist src \
    -j ACCEPT -m comment --comment "WR_WHITELIST_OUT"
iptables -I FORWARD 2 -p udp -s ${DST_IP} -j ACCEPT -m comment --comment "WR_WHITELIST_IN"
iptables -A FORWARD -p udp -d ${DST_IP} -j DROP -m comment --comment "WR_WHITELIST_DROP"

netfilter-persistent save
ipset save > /etc/ipset.rules 2>/dev/null || true

# Recipe
mkdir -p ${INSTALL_DIR}
IFACE=$(ip route | awk '/default/ {print $5; exit}')
PORTS_JSON=$(printf ',%s' "${PORTS[@]}"); PORTS_JSON="[${PORTS_JSON:1}]"
cat > ${INSTALL_DIR}/rules_recipe.json << EOF
{
  "src_ip": "${SRC_IP}",
  "dst_ip": "${DST_IP}",
  "ports": ${PORTS_JSON},
  "ipset_name": "warp_whitelist",
  "tag": "${TAG}",
  "iface": "${IFACE}"
}
EOF

# tc HTB qdisc + CONNMARK restore
if [ -n "$IFACE" ]; then
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    tc qdisc add dev "$IFACE" root handle 1: htb default 999 2>/dev/null || true
    tc class add dev "$IFACE" parent 1: classid 1:999 htb rate 1000mbit 2>/dev/null || true
    iptables -t mangle -C POSTROUTING -j CONNMARK --restore-mark 2>/dev/null || \
        iptables -t mangle -A POSTROUTING -j CONNMARK --restore-mark 2>/dev/null
fi

# ipset-restore.service (if not exists)
if [ ! -f /etc/systemd/system/ipset-restore.service ]; then
cat > /etc/systemd/system/ipset-restore.service << 'EOF'
[Unit]
Description=Restore ipset rules
Before=netfilter-persistent.service
[Service]
Type=oneshot
ExecStart=/sbin/ipset restore -f /etc/ipset.rules
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable ipset-restore.service
fi

# ═══════════════════════════════════════
# 5. BINARY FROM GITHUB RELEASES
# ═══════════════════════════════════════

echo -e "${Y}[5/7] Downloading ${BIN_NAME} from release ${RELEASE_REPO}...${N}"
DOWNLOAD_URL="https://github.com/${RELEASE_REPO}/releases/latest/download/${BIN_NAME}"
TMP_BIN="${INSTALL_DIR}/${BIN_NAME}.new"

if ! curl -fsSL -o "${TMP_BIN}" "${DOWNLOAD_URL}"; then
    echo -e "${R}  Failed to download binary from ${DOWNLOAD_URL}${N}"
    echo -e "${R}  Make sure repository ${RELEASE_REPO} has a release with asset ${BIN_NAME}${N}"
    exit 1
fi

BIN_SIZE=$(stat -c %s "${TMP_BIN}")
if [ "${BIN_SIZE}" -lt 1048576 ]; then
    echo -e "${R}  Downloaded file is too small (${BIN_SIZE} bytes) - probably corrupted${N}"
    rm -f "${TMP_BIN}"
    exit 1
fi

mv "${TMP_BIN}" "${INSTALL_DIR}/${BIN_NAME}"
chmod +x "${INSTALL_DIR}/${BIN_NAME}"
echo -e "${G}  ${BIN_NAME} installed ($(numfmt --to=iec ${BIN_SIZE}))${N}"

# ensure_rules.sh from repo
cp "${SCRIPT_DIR}/ensure_rules.sh" ${INSTALL_DIR}/ensure_rules.sh
chmod +x ${INSTALL_DIR}/ensure_rules.sh

# .env
cat > ${INSTALL_DIR}/.env << EOF
AGENT_SECRET=${AGENT_SECRET}
AGENT_PORT=${AGENT_PORT}
IPSET_NAME=warp_whitelist

RULES_WATCHDOG_INTERVAL=30
METRICS_SAMPLE_INTERVAL=1
TRAFFIC_INTERVAL=30

# Fill manually AFTER registering relay in panel:
PANEL_URL=
PANEL_API_KEY=
RELAY_ID=

REPO_DIR=${REPO_DIR}

# Override owner/repo for self-update (if fork)
# AGENT_RELEASE_REPO=user/repo
EOF

# ═══════════════════════════════════════
# 6. SYSTEMD
# ═══════════════════════════════════════

echo -e "${Y}[6/7] systemd...${N}"
cp "${SCRIPT_DIR}/warp-relay-agent.service" /etc/systemd/system/warp-relay-agent.service
systemctl daemon-reload
systemctl enable --now warp-relay-agent

sleep 2
if systemctl is-active --quiet warp-relay-agent; then
    echo -e "${G}  Agent started on :${AGENT_PORT}${N}"
else
    echo -e "${R}  Agent failed to start! journalctl -u warp-relay-agent${N}"
    exit 1
fi

# ═══════════════════════════════════════
# 7. DONE
# ═══════════════════════════════════════

echo -e "${Y}[7/7] Done${N}"
echo ""
echo -e "${G}═══════════════════════════════════════${N}"
echo -e "${G}  Relay (Go, full) configured!${N}"
echo -e "${G}═══════════════════════════════════════${N}"
echo -e "  ${C}Relay IP:${N}  ${B}${SRC_IP}${N}"
echo -e "  ${C}Agent:${N}     ${B}http://${SRC_IP}:${AGENT_PORT}${N}"
echo -e "  ${C}Binary:${N}    ${B}${INSTALL_DIR}/${BIN_NAME}${N}"
echo -e "  ${C}Release:${N}   ${B}${RELEASE_REPO}${N}"
echo ""
echo -e "  ${Y}Check:${N}  curl http://localhost:${AGENT_PORT}/health"
echo -e "  ${Y}Logs:${N}      journalctl -u warp-relay-agent -f"
echo ""
echo -e "  ${Y}Add to panel:${N}"
echo -e "  POST /api/relays {\"name\": \"$(hostname)\", \"host\": \"${SRC_IP}\", \"agent_port\": ${AGENT_PORT}, \"agent_secret\": \"${AGENT_SECRET}\"}"
echo ""
