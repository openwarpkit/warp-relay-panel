#!/bin/bash
# ═══════════════════════════════════════
# WARP Relay (MIN) - pre-flight self-heal
# Run before agent start (ExecStartPre) and periodically from watchdog.
#
# Unlike full variant: NO ipset restoration, FORWARD rules
# are simple ACCEPT (no --match-set whitelist).
# ═══════════════════════════════════════

TAG="WR_RULE"
RECIPE="${RECIPE:-/opt/warp-relay-agent/rules_recipe.json}"

G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'

# -- iptables NAT (WR_RULE) --
rebuild_from_recipe() {
    if [ ! -f "$RECIPE" ]; then
        echo -e "${R}[ensure-min] Recipe $RECIPE not found - nothing to rebuild${N}"
        return 1
    fi
    if ! command -v jq &>/dev/null; then
        echo -e "${R}[ensure-min] jq is not installed${N}"
        return 1
    fi

    SRC_IP=$(jq -r '.src_ip' "$RECIPE")
    DST_IP=$(jq -r '.dst_ip' "$RECIPE")
    PORTS=$(jq -r '.ports | join(",")' "$RECIPE")

    if [ -z "$SRC_IP" ] || [ -z "$DST_IP" ] || [ -z "$PORTS" ]; then
        echo -e "${R}[ensure-min] Recipe incomplete${N}"
        return 1
    fi

    echo -e "${Y}[ensure-min] Rebuilding NAT+FORWARD from recipe${N}"

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
    echo -e "${G}[ensure-min] NAT+FORWARD rebuilt${N}"
    return 0
}

# -- iptables NAT --
if ! iptables -t nat -S 2>/dev/null | grep -q "$TAG"; then
    echo -e "${Y}[ensure-min] iptables NAT not found${N}"
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent reload 2>/dev/null
    fi
    if ! iptables -t nat -S 2>/dev/null | grep -q "$TAG"; then
        rebuild_from_recipe || \
          echo -e "${R}[ensure-min] Run setup.sh for full setup${N}"
    fi
else
    echo "[ensure-min] iptables NAT OK"
fi

# -- iptables FORWARD ACCEPT --
if ! iptables -S FORWARD 2>/dev/null | grep -q "WR_FORWARD_OUT"; then
    echo -e "${Y}[ensure-min] FORWARD ACCEPT rules lost - rebuilding${N}"
    rebuild_from_recipe || true
fi

# -- ip_forward --
FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
if [ "$FWD" != "1" ]; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
fi

# -- tc HTB qdisc + CONNMARK restore (for shared rate-limit) --
IFACE=$(ip route | awk '/default/ {print $5; exit}')
if [ -n "$IFACE" ]; then
    if ! tc qdisc show dev "$IFACE" 2>/dev/null | grep -q "qdisc htb 1:"; then
        echo -e "${Y}[ensure-min] HTB qdisc on $IFACE not found - creating${N}"
        tc qdisc add dev "$IFACE" root handle 1: htb default 999 2>/dev/null
        tc class add dev "$IFACE" parent 1: classid 1:999 htb rate 1000mbit 2>/dev/null
    fi
    if ! iptables -t mangle -S POSTROUTING 2>/dev/null | grep -q "CONNMARK --restore-mark"; then
        iptables -t mangle -A POSTROUTING -j CONNMARK --restore-mark 2>/dev/null
    fi
fi

# -- nftables warp_shaper (per-IP CONNMARK via O(1) map lookup) --
# Replaces N "iptables -t mangle PREROUTING -m conntrack --ctorigsrc IP -j CONNMARK"
# with one common hash-map construct. On 200+ IPs gives colossal CPU reduction in softirq.
# Switch: RATELIMIT_BACKEND=iptables in systemd unit -> skip nft initialization.
if [ "${RATELIMIT_BACKEND:-nftables}" != "iptables" ] && ! command -v nft &>/dev/null; then
    # On existing relays after self-update nft may be missing -
    # install once non-interactively. If apt is unavailable - graceful fallback below.
    echo -e "${Y}[ensure-min] nft not installed, installing apt package nftables...${N}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables 2>/dev/null || \
        echo -e "${R}[ensure-min] apt install nftables failed - continuing in legacy iptables mode${N}"
fi
if [ "${RATELIMIT_BACKEND:-nftables}" != "iptables" ] && command -v nft &>/dev/null; then
    if ! nft list table ip warp_shaper >/dev/null 2>&1; then
        echo -e "${Y}[ensure-min] nft: creating table ip warp_shaper${N}"
        nft add table ip warp_shaper
        nft add chain ip warp_shaper prerouting \
            "{ type filter hook prerouting priority -150 ; }"
        nft add map ip warp_shaper ip2mark \
            "{ type ipv4_addr : mark ; }"
        nft add rule ip warp_shaper prerouting \
            ct mark set ip saddr map @ip2mark
    fi

    # Migration iptables -> nft. Do this BEFORE creating flow filter, so there's no
    # prio conflict with orphaned fw-filters from past life.
    # iptables prints "--set-xmark 0xM/0xffffffff" (new iptables-nft format);
    # old "--set-mark" is also caught just in case.
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
        # Migration: remove old per-IP fw filters. BEFORE creating flow filter,
        # otherwise flow won't be inserted - "Specified filter kind does not match existing one".
        # Grep searches for any handles in fw-filters on parent 1:0.
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

        # One root tc flow filter routes packets to class 1:<mark> in O(1).
        # Replaces N "tc filter ... fw flowid 1:M" calls with a single one.
        #
        # Syntax: "flow map key mark addend 0xffffffff baseclass 1:1"
        #   - "key mark" (singular, not "keys nfmark" - different name in iproute2 6.x)
        #   - "baseclass 1:1" - default for map mode (explicit 1:0 gives "Illegal baseclass")
        #   - "addend 0xffffffff" = +(-1) -> result: classid = (1:1) + (mark - 1) = 1:mark
        # Without addend classid would be 1:(mark+1) - mismatch with HTB class 1:mark.
        if ! tc filter show dev "$IFACE" parent 1:0 2>/dev/null | grep -q "flow map"; then
            echo -e "${Y}[ensure-min] tc: creating root flow filter on $IFACE${N}"
            tc filter add dev "$IFACE" parent 1:0 protocol ip prio 1 \
                handle 1 flow map key mark addend 0xffffffff baseclass 1:1 2>&1 || \
                echo -e "${R}[ensure-min] tc flow filter not created${N}"
        fi
    fi
elif [ "${RATELIMIT_BACKEND:-nftables}" != "iptables" ]; then
    echo -e "${Y}[ensure-min] nft not installed - running in legacy iptables mode${N}"
fi

echo "[ensure-min] Done"
