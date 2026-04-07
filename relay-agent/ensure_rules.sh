#!/bin/bash
# ═══════════════════════════════════════
# WARP Relay — восстановление правил
# Вызывается перед стартом агента (ExecStartPre)
# Проверяет ipset и iptables, восстанавливает если пропали
# ═══════════════════════════════════════

IPSET_NAME="${IPSET_NAME:-warp_whitelist}"
TAG="WR_RULE"

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
            ipset create "$IPSET_NAME" hash:ip 2>/dev/null
        fi
    else
        echo -e "${Y}[ensure] /etc/ipset.rules не найден, создаём пустой ipset${N}"
        ipset create "$IPSET_NAME" hash:ip 2>/dev/null
    fi
else
    echo "[ensure] ipset '$IPSET_NAME' OK"
fi

# ── iptables (проверяем наличие WR_RULE) ──
if ! iptables -t nat -S 2>/dev/null | grep -q "$TAG"; then
    echo -e "${Y}[ensure] iptables NAT правила не найдены${N}"
    if command -v netfilter-persistent &>/dev/null; then
        echo -e "${Y}[ensure] Восстанавливаем через netfilter-persistent...${N}"
        netfilter-persistent reload 2>/dev/null
        if iptables -t nat -S 2>/dev/null | grep -q "$TAG"; then
            echo -e "${G}[ensure] iptables восстановлены${N}"
        else
            echo -e "${R}[ensure] netfilter-persistent не помог — правила нужно переприменить${N}"
            echo -e "${R}[ensure] Запустите: bash /opt/warp-relay-panel/relay-agent/setup_relay.sh${N}"
        fi
    else
        echo -e "${R}[ensure] netfilter-persistent не установлен${N}"
        echo -e "${R}[ensure] Запустите setup_relay.sh для полной настройки${N}"
    fi
else
    echo "[ensure] iptables rules OK"
fi

# ── ip_forward ──
FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
if [ "$FWD" != "1" ]; then
    echo -e "${Y}[ensure] ip_forward выключен, включаем...${N}"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
fi

echo "[ensure] Done"