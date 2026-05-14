#!/bin/bash
# ═══════════════════════════════════════
# WARP Relay (Go) — full setup
# Запуск: sudo bash setup.sh
#
# Делает: установка пакетов, настройка iptables/ipset/tc,
# установка Go, сборка бинаря, systemd unit.
# Заменяет relay-agent/setup_relay.sh для Go-агента.
# ═══════════════════════════════════════

set -e

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; N='\033[0m'; B='\033[1m'

echo -e "${B}═══════════════════════════════════════${N}"
echo -e "${B}  WARP Relay (Go) — Full Setup${N}"
echo -e "${B}═══════════════════════════════════════${N}"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${R}Запустите от root: sudo bash $0${N}"
    exit 1
fi

read -p "Agent secret (общий с панелью): " AGENT_SECRET
read -p "Agent port [7580]: " AGENT_PORT
AGENT_PORT=${AGENT_PORT:-7580}

INSTALL_DIR="/opt/warp-relay-agent"
TAG="WR_RULE"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GO_AGENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"   # …/relay-agent-go
REPO_DIR="$(cd "${GO_AGENT_DIR}/.." && pwd)"     # …/warp-relay-panel

# ═══════════════════════════════════════
# 1. ПАКЕТЫ
# ═══════════════════════════════════════

echo -e "${Y}[1/8] Установка пакетов...${N}"
export DEBIAN_FRONTEND=noninteractive
apt update -qq
apt install -y -qq iptables ipset curl conntrack netfilter-persistent ipset-persistent git jq iproute2 build-essential

# ═══════════════════════════════════════
# 2. GO TOOLCHAIN
# ═══════════════════════════════════════

echo -e "${Y}[2/8] Проверка Go тулчейна...${N}"
GO_VERSION="1.22.5"
if ! command -v go &>/dev/null || [[ "$(go version | awk '{print $3}')" < "go${GO_VERSION}" ]]; then
    ARCH=$(dpkg --print-architecture)
    case "$ARCH" in
        amd64) GOARCH="amd64" ;;
        arm64) GOARCH="arm64" ;;
        *) echo -e "${R}Неизвестная архитектура: $ARCH${N}"; exit 1 ;;
    esac
    echo -e "${Y}  Скачиваем Go ${GO_VERSION}-${GOARCH}...${N}"
    cd /tmp
    curl -sLO "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    rm -f "go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    ln -sf /usr/local/go/bin/go /usr/local/bin/go
    echo -e "${G}  Go ${GO_VERSION} установлен${N}"
else
    echo -e "${G}  Go уже установлен: $(go version)${N}"
fi

# ═══════════════════════════════════════
# 3. СИСТЕМА (sysctl, timezone)
# ═══════════════════════════════════════

echo -e "${Y}[3/8] Настройка системы...${N}"
timedatectl set-timezone Europe/Moscow 2>/dev/null || ln -sf /usr/share/zoneinfo/Europe/Moscow /etc/localtime
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/ipv4-forwarding.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.netfilter.nf_conntrack_acct=1" > /etc/sysctl.d/conntrack-acct.conf
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true

# ═══════════════════════════════════════
# 4. IPSET
# ═══════════════════════════════════════

echo -e "${Y}[4/8] ipset...${N}"
if ! ipset list warp_whitelist &>/dev/null; then
    ipset create warp_whitelist hash:ip maxelem 1000000
fi

# ═══════════════════════════════════════
# 5. IPTABLES + RECIPE
# ═══════════════════════════════════════

echo -e "${Y}[5/8] iptables NAT/FORWARD...${N}"
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

# ipset-restore.service (если ещё нет)
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
# 6. BUILD GO BINARY
# ═══════════════════════════════════════

echo -e "${Y}[6/8] Сборка warp-relay-agent...${N}"
cd "${GO_AGENT_DIR}"
make tidy
make build
cp bin/warp-relay-agent ${INSTALL_DIR}/warp-relay-agent
chmod +x ${INSTALL_DIR}/warp-relay-agent
echo -e "${G}  $(${INSTALL_DIR}/warp-relay-agent --help 2>/dev/null || echo 'binary установлен')${N}"

# ensure_rules.sh из Python-агента (общий)
cp "${REPO_DIR}/relay-agent/ensure_rules.sh" ${INSTALL_DIR}/ensure_rules.sh
chmod +x ${INSTALL_DIR}/ensure_rules.sh

# .env
cat > ${INSTALL_DIR}/.env << EOF
AGENT_SECRET=${AGENT_SECRET}
AGENT_PORT=${AGENT_PORT}
IPSET_NAME=warp_whitelist

RULES_WATCHDOG_INTERVAL=30
METRICS_SAMPLE_INTERVAL=1
TRAFFIC_INTERVAL=30

# Заполнить вручную ПОСЛЕ регистрации relay в панели:
PANEL_URL=
PANEL_API_KEY=
RELAY_ID=

REPO_DIR=${REPO_DIR}
EOF

# ═══════════════════════════════════════
# 7. SYSTEMD
# ═══════════════════════════════════════

echo -e "${Y}[7/8] systemd...${N}"
cp "${SCRIPT_DIR}/warp-relay-agent.service" /etc/systemd/system/warp-relay-agent.service
systemctl daemon-reload
systemctl enable --now warp-relay-agent

sleep 2
if systemctl is-active --quiet warp-relay-agent; then
    echo -e "${G}  Agent запущен на :${AGENT_PORT}${N}"
else
    echo -e "${R}  Agent не запустился! journalctl -u warp-relay-agent${N}"
    exit 1
fi

# ═══════════════════════════════════════
# 8. ИТОГ
# ═══════════════════════════════════════

echo -e "${Y}[8/8] Готово${N}"
echo ""
echo -e "${G}═══════════════════════════════════════${N}"
echo -e "${G}  Relay (Go) настроен!${N}"
echo -e "${G}═══════════════════════════════════════${N}"
echo -e "  ${C}Relay IP:${N}  ${B}${SRC_IP}${N}"
echo -e "  ${C}Agent:${N}     ${B}http://${SRC_IP}:${AGENT_PORT}${N}"
echo -e "  ${C}Версия:${N}    ${B}v2.0.0 (Go)${N}"
echo -e "  ${C}Бинарь:${N}    ${B}${INSTALL_DIR}/warp-relay-agent${N}"
echo ""
echo -e "  ${Y}Проверка:${N}  curl http://localhost:${AGENT_PORT}/health"
echo -e "  ${Y}Логи:${N}      journalctl -u warp-relay-agent -f"
echo ""
echo -e "  ${Y}Добавить в панель:${N}"
echo -e "  POST /api/relays {\"name\": \"$(hostname)\", \"host\": \"${SRC_IP}\", \"agent_port\": ${AGENT_PORT}}"
echo ""
