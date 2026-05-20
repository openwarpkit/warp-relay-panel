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

# ── nftables warp_shaper (per-IP CONNMARK через O(1) map lookup) ──
# Заменяет N штук "iptables -t mangle PREROUTING -m conntrack --ctorigsrc IP -j CONNMARK"
# одной общей конструкцией с hash-map. На 200+ IP даёт колоссальное снижение CPU в softirq.
# Переключатель: RATELIMIT_BACKEND=iptables в systemd unit → пропустить nft-инициализацию.
if [ "${RATELIMIT_BACKEND:-nftables}" != "iptables" ] && ! command -v nft &>/dev/null; then
    # На существующих relay'ях после self-update nft может отсутствовать —
    # ставим один раз без интерактива. Если apt недоступен — graceful fallback ниже.
    echo -e "${Y}[ensure-min] nft не установлен, ставим apt-пакет nftables...${N}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables 2>/dev/null || \
        echo -e "${R}[ensure-min] apt install nftables не удался — продолжаем в legacy iptables-режиме${N}"
fi
if [ "${RATELIMIT_BACKEND:-nftables}" != "iptables" ] && command -v nft &>/dev/null; then
    if ! nft list table ip warp_shaper >/dev/null 2>&1; then
        echo -e "${Y}[ensure-min] nft: создаём table ip warp_shaper${N}"
        nft add table ip warp_shaper
        nft add chain ip warp_shaper prerouting \
            "{ type filter hook prerouting priority -150 ; }"
        nft add map ip warp_shaper ip2mark \
            "{ type ipv4_addr : mark ; }"
        nft add rule ip warp_shaper prerouting \
            ct mark set ip saddr map @ip2mark
    fi

    # Миграция iptables → nft. Делаем ДО создания flow filter'а, чтобы не было
    # конфликта prio с осиротевшими fw-фильтрами от прошлой жизни.
    # iptables печатает "--set-xmark 0xM/0xffffffff" (новый формат iptables-nft);
    # старый "--set-mark" тоже ловим на всякий случай.
    REMOVED=0
    while IFS= read -r rule; do
        if [ -n "$rule" ]; then
            DEL_RULE=$(echo "$rule" | sed 's/^-A/-D/')
            iptables -t mangle $DEL_RULE 2>/dev/null && REMOVED=$((REMOVED+1)) || true
        fi
    done < <(iptables -t mangle -S PREROUTING 2>/dev/null | \
             grep -E '\-m conntrack --ctorigsrc .* -j CONNMARK --set-(x)?mark')
    if [ "$REMOVED" -gt 0 ]; then
        echo -e "${G}[ensure-min] migrated $REMOVED iptables-mangle rule(s) to nftables${N}"
    fi

    if [ -n "$IFACE" ]; then
        # Миграция: убрать старые per-IP fw filter'ы. ДО создания flow filter,
        # иначе flow не вставится — "Specified filter kind does not match existing one".
        # Grep ищет любые handle'ы у fw-фильтров на parent 1:0.
        REMOVED_FW=0
        while IFS= read -r handle; do
            if [ -n "$handle" ]; then
                tc filter del dev "$IFACE" parent 1:0 prio 1 handle "$handle" fw 2>/dev/null && \
                    REMOVED_FW=$((REMOVED_FW+1)) || true
            fi
        done < <(tc filter show dev "$IFACE" parent 1:0 2>/dev/null | \
                 grep -oP 'fw chain \S+ handle \K0x[0-9a-f]+' | sort -u)
        if [ "$REMOVED_FW" -gt 0 ]; then
            echo -e "${G}[ensure-min] migrated $REMOVED_FW tc fw-filter(s) to flow-map${N}"
        fi

        # Один root tc flow filter маршрутизирует пакеты в class 1:<mark> за O(1).
        # Заменяет N штук "tc filter ... fw flowid 1:M" одним вызовом.
        #
        # Синтаксис: "flow map key mark addend 0xffffffff baseclass 1:1"
        #   - "key mark" (singular, не "keys nfmark" — это другое имя в iproute2 6.x)
        #   - "baseclass 1:1" — дефолт для map-режима (явный 1:0 у нас даёт "Illegal baseclass")
        #   - "addend 0xffffffff" = +(-1) → итог: classid = (1:1) + (mark - 1) = 1:mark
        # Без addend classid был бы 1:(mark+1) — несовпадение с HTB-классом 1:mark.
        if ! tc filter show dev "$IFACE" parent 1:0 2>/dev/null | grep -q "flow map"; then
            echo -e "${Y}[ensure-min] tc: создаём root flow filter на $IFACE${N}"
            tc filter add dev "$IFACE" parent 1:0 protocol ip prio 1 \
                handle 1 flow map key mark addend 0xffffffff baseclass 1:1 2>&1 || \
                echo -e "${R}[ensure-min] tc flow filter не создан${N}"
        fi
    fi
elif [ "${RATELIMIT_BACKEND:-nftables}" != "iptables" ]; then
    echo -e "${Y}[ensure-min] nft не установлен — выполняется в legacy iptables-режиме${N}"
fi

echo "[ensure-min] Done"
