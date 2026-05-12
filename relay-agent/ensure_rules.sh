#!/bin/bash
# ═══════════════════════════════════════
# WARP Relay — восстановление правил
# Вызывается перед стартом агента (ExecStartPre)
# и периодически из watchdog'а агента.
# ═══════════════════════════════════════

IPSET_NAME="${IPSET_NAME:-warp_whitelist}"
TAG="WR_RULE"
RECIPE="${RECIPE:-/opt/warp-relay-agent/rules_recipe.json}"

G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'

# ── ipset ──
if ! ipset list "$IPSET_NAME" &>/dev/null; then
    echo -e "${Y}[ensure] ipset '$IPSET_NAME' не найден${N}"
    if [ -f /etc/ipset.rules ]; then
        echo -e "${Y}[ensure] Восстанавливаем из /etc/ipset.rules...${N}"
        ipset restore -f /etc/ipset.rules 2>/dev/null
        if ipset list "$IPSET_NAME" &>/dev/null; then
            echo -e "${G}[ensure] ipset восстановлен${N}"
        else
            echo -e "${R}[ensure] Не удалось восстановить, создаём пустой${N}"
            ipset create "$IPSET_NAME" hash:ip maxelem 1000000 2>/dev/null
        fi
    else
        echo -e "${Y}[ensure] /etc/ipset.rules не найден, создаём пустой ipset${N}"
        ipset create "$IPSET_NAME" hash:ip maxelem 1000000 2>/dev/null
    fi
else
    echo "[ensure] ipset '$IPSET_NAME' OK"
fi

# ── iptables NAT (WR_RULE) ──
rebuild_from_recipe() {
    if [ ! -f "$RECIPE" ]; then
        echo -e "${R}[ensure] Recipe $RECIPE не найден — пересобрать NAT нечем${N}"
        return 1
    fi
    if ! command -v jq &>/dev/null; then
        echo -e "${R}[ensure] jq не установлен — recipe прочитать нечем${N}"
        return 1
    fi

    SRC_IP=$(jq -r '.src_ip' "$RECIPE")
    DST_IP=$(jq -r '.dst_ip' "$RECIPE")
    PORTS=$(jq -r '.ports | join(",")' "$RECIPE")
    IFACE=$(jq -r '.iface // empty' "$RECIPE")

    if [ -z "$SRC_IP" ] || [ -z "$DST_IP" ] || [ -z "$PORTS" ]; then
        echo -e "${R}[ensure] Recipe неполный (src/dst/ports)${N}"
        return 1
    fi

    echo -e "${Y}[ensure] Пересобираем NAT из recipe: src=$SRC_IP dst=$DST_IP${N}"

    # Чистим возможные обрывки правил с тэгом
    iptables -t nat -S 2>/dev/null | grep "$TAG" | sed 's/^-A/-D/' | while read rule; do
        iptables -t nat $rule 2>/dev/null || true
    done
    iptables -S 2>/dev/null | grep "WR_WHITELIST" | sed 's/^-A/-D/' | while read rule; do
        iptables $rule 2>/dev/null || true
    done

    # PREROUTING/POSTROUTING чанками по 15 портов (ограничение multiport)
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
    done

    iptables -I FORWARD 1 -p udp -d "$DST_IP" \
        -m set --match-set "$IPSET_NAME" src \
        -j ACCEPT \
        -m comment --comment "WR_WHITELIST_OUT" 2>/dev/null
    iptables -I FORWARD 2 -p udp -s "$DST_IP" \
        -j ACCEPT \
        -m comment --comment "WR_WHITELIST_IN" 2>/dev/null
    iptables -A FORWARD -p udp -d "$DST_IP" \
        -j DROP \
        -m comment --comment "WR_WHITELIST_DROP" 2>/dev/null

    netfilter-persistent save 2>/dev/null || true
    echo -e "${G}[ensure] NAT пересобран из recipe${N}"
    return 0
}

if ! iptables -t nat -S 2>/dev/null | grep -q "$TAG"; then
    echo -e "${Y}[ensure] iptables NAT правила не найдены${N}"
    if command -v netfilter-persistent &>/dev/null; then
        echo -e "${Y}[ensure] Восстанавливаем через netfilter-persistent...${N}"
        netfilter-persistent reload 2>/dev/null
    fi
    if ! iptables -t nat -S 2>/dev/null | grep -q "$TAG"; then
        echo -e "${Y}[ensure] netfilter-persistent не помог — пробуем recipe${N}"
        rebuild_from_recipe || \
          echo -e "${R}[ensure] Запустите setup_relay.sh для полной настройки${N}"
    else
        echo -e "${G}[ensure] iptables восстановлены${N}"
    fi
else
    echo "[ensure] iptables NAT rules OK"
fi

# ── iptables FORWARD whitelist (WR_WHITELIST_OUT/IN) ──
if ! iptables -S FORWARD 2>/dev/null | grep -q "WR_WHITELIST_OUT"; then
    echo -e "${Y}[ensure] FORWARD whitelist правила потеряны — пересобираем${N}"
    rebuild_from_recipe || true
fi

# ── ip_forward ──
FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
if [ "$FWD" != "1" ]; then
    echo -e "${Y}[ensure] ip_forward выключен, включаем...${N}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
fi

# ── tc HTB root qdisc для rate-limit'ов ──
IFACE=$(ip route | awk '/default/ {print $5; exit}')
if [ -n "$IFACE" ]; then
    if ! tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "qdisc htb 1:"; then
        echo -e "${Y}[ensure] HTB qdisc на $IFACE не найден — создаём${N}"
        tc qdisc add dev "$IFACE" root handle 1: htb default 999 2>/dev/null
        tc class add dev "$IFACE" parent 1: classid 1:999 htb rate 1000mbit 2>/dev/null
    fi
    # CONNMARK restore на egress (для rate-limit'ов)
    if ! iptables -t mangle -S POSTROUTING 2>/dev/null | grep -q "CONNMARK --restore-mark"; then
        iptables -t mangle -A POSTROUTING -j CONNMARK --restore-mark 2>/dev/null
    fi
fi

echo "[ensure] Done"
