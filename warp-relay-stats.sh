#!/usr/bin/env bash
set -Eeuo pipefail

INTERVAL="${1:-2}"
TOP="${TOP:-8}"
RECIPE="${RECIPE:-/opt/warp-relay-agent/rules_recipe.json}"
TRAFFIC_FILE="${TRAFFIC_FILE:-/opt/warp-relay-agent/traffic.json}"

[[ "$EUID" -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ -t 1 && -r /dev/tty ]] || { echo "Interactive terminal required"; exit 1; }
[[ "$INTERVAL" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "Invalid refresh interval"; exit 1; }
awk -v value="$INTERVAL" 'BEGIN { exit !(value >= 0.5) }' || {
    echo "Refresh interval must be at least 0.5 seconds"
    exit 1
}
[[ "$TOP" =~ ^[0-9]+$ ]] && (( TOP >= 1 && TOP <= 30 )) || {
    echo "TOP must be between 1 and 30"
    exit 1
}
[[ -f "$RECIPE" ]] || { echo "Recipe not found: $RECIPE"; exit 1; }

for command_name in awk conntrack date grep ip iptables jq sort systemctl tc tput; do
    command -v "$command_name" >/dev/null || {
        echo "Required command not found: $command_name"
        exit 1
    }
done

DST_IP="$(jq -r '.dst_ip // empty' "$RECIPE")"
IFACE="$(jq -r '.iface // empty' "$RECIPE")"
PORTS="$(jq -r '.ports | join(",")' "$RECIPE")"
[[ -n "$IFACE" ]] || IFACE="$(ip route | awk '/default/ {print $5; exit}')"
[[ -n "$DST_IP" && -n "$IFACE" && -n "$PORTS" ]] || {
    echo "Incomplete WARP relay recipe"
    exit 1
}
[[ -d "/sys/class/net/$IFACE" ]] || { echo "Interface not found: $IFACE"; exit 1; }

ACCT_FILE="/proc/sys/net/netfilter/nf_conntrack_acct"
if [[ -r "$ACCT_FILE" ]]; then
    if [[ -w "$ACCT_FILE" && "$(< "$ACCT_FILE")" != "1" ]]; then
        printf '1\n' > "$ACCT_FILE"
    fi
    [[ "$(< "$ACCT_FILE")" == "1" ]] || {
        echo "Conntrack byte accounting is disabled"
        exit 1
    }
fi

TMP_DIR="$(mktemp -d)"
PREVIOUS="$TMP_DIR/previous.tsv"
CURRENT="$TMP_DIR/current.tsv"
AGGREGATE="$TMP_DIR/aggregate.tsv"

cleanup() {
    printf '\033[?25h\033[0m\n'
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT
trap 'exit 130' INT TERM HUP

if [[ "${TERM:-}" != "dumb" ]]; then
    RESET=$'\033[0m'
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    CYAN=$'\033[36m'
else
    RESET=""
    BOLD=""
    DIM=""
    RED=""
    GREEN=""
    YELLOW=""
    CYAN=""
fi

capture_flows() {
    local output="$1"
    conntrack -L -p udp -o extended 2>/dev/null |
        awk -v target="$DST_IP" -v allowed="$PORTS" '
            BEGIN {
                FS = " "
                OFS = "\t"
                count = split(allowed, list, ",")
                for (i = 1; i <= count; i++) ports[list[i]] = 1
            }
            {
                tuple = 0
                source = destination = sourcePort = destinationPort = ""
                replySource = ""
                originalBytes = replyBytes = 0
                assured = unreplied = 0
                for (i = 1; i <= NF; i++) {
                    if ($i == "[ASSURED]") assured = 1
                    if ($i == "[UNREPLIED]") unreplied = 1
                    split($i, pair, "=")
                    if (pair[1] == "src") {
                        tuple++
                        if (tuple == 1) source = pair[2]
                        if (tuple == 2) replySource = pair[2]
                    } else if (tuple == 1 && pair[1] == "dst") {
                        destination = pair[2]
                    } else if (tuple == 1 && pair[1] == "sport") {
                        sourcePort = pair[2]
                    } else if (tuple == 1 && pair[1] == "dport") {
                        destinationPort = pair[2]
                    } else if (tuple == 1 && pair[1] == "bytes") {
                        originalBytes = pair[2]
                    } else if (tuple == 2 && pair[1] == "bytes") {
                        replyBytes = pair[2]
                    }
                }
                if (replySource == target && (destinationPort in ports) && source != "") {
                    key = source "|" destination "|" sourcePort "|" destinationPort
                    print key, source, destinationPort, originalBytes, replyBytes, assured, unreplied
                }
            }
        ' > "$output" || true
}

aggregate_flows() {
    local elapsed="$1"
    awk -F '\t' -v dt="$elapsed" '
        FILENAME == ARGV[1] {
            previousTX[$1] = $4
            previousRX[$1] = $5
            next
        }
        FILENAME == ARGV[2] {
            key = $1
            ip = $2
            port = $3
            sessionsPort[port]++
            sessionsIP[ip]++
            sessionsTotal++
            portIP = port SUBSEP ip
            if (!(portIP in seenPortIP)) {
                seenPortIP[portIP] = 1
                clientsPort[port]++
            }
            if (!(ip in seenIP)) {
                seenIP[ip] = 1
                clientsTotal++
            }
            if ($6) {
                assuredPort[port]++
                assuredIP[ip]++
                assuredTotal++
            }
            if ($7) {
                unrepliedPort[port]++
                unrepliedIP[ip]++
                unrepliedTotal++
            }
            if (key in previousTX) {
                deltaTX = $4 - previousTX[key]
                deltaRX = $5 - previousRX[key]
                if (deltaTX < 0) deltaTX = 0
                if (deltaRX < 0) deltaRX = 0
                txPort[port] += deltaTX
                rxPort[port] += deltaRX
                txIP[ip] += deltaTX
                rxIP[ip] += deltaRX
                txTotal += deltaTX
                rxTotal += deltaRX
            }
        }
        END {
            for (port in sessionsPort) {
                tx = txPort[port] / dt
                rx = rxPort[port] / dt
                printf "P\t%s\t%d\t%d\t%d\t%.0f\t%.0f\t%.0f\t%d\n", port,
                    sessionsPort[port], assuredPort[port], unrepliedPort[port], tx, rx, tx + rx,
                    clientsPort[port]
            }
            for (ip in sessionsIP) {
                tx = txIP[ip] / dt
                rx = rxIP[ip] / dt
                printf "I\t%s\t%d\t%d\t%d\t%.0f\t%.0f\t%.0f\t1\n", ip,
                    sessionsIP[ip], assuredIP[ip], unrepliedIP[ip], tx, rx, tx + rx
            }
            tx = txTotal / dt
            rx = rxTotal / dt
            printf "T\t-\t%d\t%d\t%d\t%.0f\t%.0f\t%.0f\t%d\n", sessionsTotal,
                assuredTotal, unrepliedTotal, tx, rx, tx + rx, clientsTotal
        }
    ' "$PREVIOUS" "$CURRENT" > "$AGGREGATE"
}

read_counter() {
    local path="$1"
    if [[ -r "$path" ]]; then
        tr -d '[:space:]' < "$path"
    else
        printf '0'
    fi
}

format_rate() {
    awk -v bytes="${1:-0}" 'BEGIN {
        bits = bytes * 8
        if (bits >= 1000000000) printf "%.2f Gbps", bits / 1000000000
        else if (bits >= 1000000) printf "%.1f Mbps", bits / 1000000
        else if (bits >= 1000) printf "%.1f Kbps", bits / 1000
        else printf "%.0f bps", bits
    }'
}

format_bytes() {
    awk -v bytes="${1:-0}" 'BEGIN {
        if (bytes >= 1099511627776) printf "%.2f TiB", bytes / 1099511627776
        else if (bytes >= 1073741824) printf "%.2f GiB", bytes / 1073741824
        else if (bytes >= 1048576) printf "%.1f MiB", bytes / 1048576
        else if (bytes >= 1024) printf "%.1f KiB", bytes / 1024
        else printf "%.0f B", bytes
    }'
}

monthly_totals() {
    if [[ -r "$TRAFFIC_FILE" ]] && jq -e . "$TRAFFIC_FILE" >/dev/null 2>&1; then
        jq -r '
            ((([.ips[]? | (.tx // 0)] | add) // 0) + (.orphaned_tx // 0) + (.agg_tx // 0)) as $tx |
            ((([.ips[]? | (.rx // 0)] | add) // 0) + (.orphaned_rx // 0) + (.agg_rx // 0)) as $rx |
            [$tx, $rx, (.month // "-")] | @tsv
        ' "$TRAFFIC_FILE"
    else
        printf '0\t0\t-\n'
    fi
}

render_table() {
    local kind="$1"
    local limit="$2"
    local denominator="$3"
    if [[ "$kind" == "P" ]]; then
        printf '%-7s %11s %11s %11s %6s %7s %6s  %s\n' \
            "PORT" "DOWN" "UP" "TOTAL" "SESS" "CLIENTS" "UNR" "SHARE"
    else
        printf '%-15s %11s %11s %11s %6s %6s  %s\n' "CLIENT IP" "DOWN" "UP" "TOTAL" "SESS" "UNR" "SHARE"
    fi
    awk -F '\t' -v kind="$kind" '$1 == kind' "$AGGREGATE" |
        sort -t $'\t' -k8,8nr |
        awk -F '\t' -v kind="$kind" -v denominator="$denominator" -v limit="$limit" '
            function rate(bytes, bits) {
                bits = bytes * 8
                if (bits >= 1000000000) return sprintf("%.2f Gbps", bits / 1000000000)
                if (bits >= 1000000) return sprintf("%.1f Mbps", bits / 1000000)
                if (bits >= 1000) return sprintf("%.1f Kbps", bits / 1000)
                return sprintf("%.0f bps", bits)
            }
            function bar(value, total, percent, filled, i, output) {
                percent = 0
                if (total > 0) percent = int(value * 100 / total + 0.5)
                if (percent > 100) percent = 100
                filled = int(percent * 12 / 100)
                output = "["
                for (i = 0; i < 12; i++) {
                    if (i < filled) output = output "#"
                    else output = output "."
                }
                return output "] " sprintf("%3d%%", percent)
            }
            {
                if (NR > limit) next
                width = 15
                if (kind == "P") width = 7
                if (kind == "P") {
                    printf "%-*s %11s %11s %11s %6d %7d %6d  %s\n", width, $2,
                        rate($7), rate($6), rate($8), $3, $9, $5, bar($8, denominator)
                } else {
                    printf "%-*s %11s %11s %11s %6d %6d  %s\n", width, $2,
                        rate($7), rate($6), rate($8), $3, $5, bar($8, denominator)
                }
            }
        '
}

capture_flows "$PREVIOUS"
PREVIOUS_RX="$(read_counter "/sys/class/net/$IFACE/statistics/rx_bytes")"
PREVIOUS_TX="$(read_counter "/sys/class/net/$IFACE/statistics/tx_bytes")"
PREVIOUS_TIME="$(date +%s%N)"

printf '\033[?25l\033[2J\033[H'
printf '%bCollecting first traffic sample for %s seconds...%b\n' "$CYAN" "$INTERVAL" "$RESET"

while true; do
    KEY=""
    if IFS= read -rsn1 -t "$INTERVAL" KEY < /dev/tty; then
        case "$KEY" in
            q|Q) break ;;
        esac
    fi

    capture_flows "$CURRENT"
    CURRENT_TIME="$(date +%s%N)"
    CURRENT_RX="$(read_counter "/sys/class/net/$IFACE/statistics/rx_bytes")"
    CURRENT_TX="$(read_counter "/sys/class/net/$IFACE/statistics/tx_bytes")"
    ELAPSED="$(awk -v start="$PREVIOUS_TIME" -v finish="$CURRENT_TIME" 'BEGIN {
        value = (finish - start) / 1000000000
        if (value <= 0) value = 1
        printf "%.6f", value
    }')"

    aggregate_flows "$ELAPSED"

    IFACE_RX_RATE="$(awk -v current="$CURRENT_RX" -v previous="$PREVIOUS_RX" -v elapsed="$ELAPSED" 'BEGIN {
        delta = 0
        if (current >= previous) delta = current - previous
        printf "%.0f", delta / elapsed
    }')"
    IFACE_TX_RATE="$(awk -v current="$CURRENT_TX" -v previous="$PREVIOUS_TX" -v elapsed="$ELAPSED" 'BEGIN {
        delta = 0
        if (current >= previous) delta = current - previous
        printf "%.0f", delta / elapsed
    }')"

    TOTAL_LINE="$(awk -F '\t' '$1 == "T" { print; exit }' "$AGGREGATE")"
    IFS=$'\t' read -r _ _ SESSIONS ASSURED UNREPLIED WARP_TX WARP_RX WARP_TOTAL CLIENTS_TOTAL <<< "$TOTAL_LINE"
    SESSIONS="${SESSIONS:-0}"
    ASSURED="${ASSURED:-0}"
    UNREPLIED="${UNREPLIED:-0}"
    WARP_TX="${WARP_TX:-0}"
    WARP_RX="${WARP_RX:-0}"
    WARP_TOTAL="${WARP_TOTAL:-0}"
    CLIENTS_TOTAL="${CLIENTS_TOTAL:-0}"

    IFS=$'\t' read -r MONTH_TX MONTH_RX TRAFFIC_MONTH <<< "$(monthly_totals)"
    CT_COUNT="$(read_counter /proc/sys/net/netfilter/nf_conntrack_count)"
    CT_MAX="$(read_counter /proc/sys/net/netfilter/nf_conntrack_max)"
    CT_PERCENT="$(awk -v count="$CT_COUNT" -v maximum="$CT_MAX" 'BEGIN {
        percent = 0
        if (maximum > 0) percent = count * 100 / maximum
        printf "%.1f", percent
    }')"
    LOAD_AVERAGE="$(awk '{ print $1 " " $2 " " $3 }' /proc/loadavg)"
    MEMORY="$(awk '/MemTotal:/ { total=$2 } /MemAvailable:/ { available=$2 } END {
        used=total-available
        percent=0
        if (total > 0) percent=used*100/total
        printf "%.0f/%.0f MiB (%.1f%%)", used/1024, total/1024, percent
    }' /proc/meminfo)"
    RX_DROPPED="$(read_counter "/sys/class/net/$IFACE/statistics/rx_dropped")"
    TX_DROPPED="$(read_counter "/sys/class/net/$IFACE/statistics/tx_dropped")"

    if systemctl is-active --quiet warp-relay-agent.service; then
        AGENT_STATUS="${GREEN}ACTIVE${RESET}"
    else
        AGENT_STATUS="${RED}INACTIVE${RESET}"
    fi

    LIMIT_STATUS="${DIM}off${RESET}"
    IP_HISTORY_STATUS="${DIM}collector off${RESET}"
    LIMIT_IPS_FILE=""
    if systemctl is-active --quiet warp-port-limit.service && [[ -r /etc/default/warp-port-limit ]]; then
        LIMIT_PORT="$(awk -F '=' '$1 == "PORT" { print $2; exit }' /etc/default/warp-port-limit)"
        LIMIT_MBPS="$(awk -F '=' '$1 == "MBPS" { print $2; exit }' /etc/default/warp-port-limit)"
        LIMIT_RATE="$(awk -F '\t' -v port="$LIMIT_PORT" '$1 == "P" && $2 == port { print $8; exit }' "$AGGREGATE")"
        LIMIT_CLIENTS="$(awk -F '\t' -v port="$LIMIT_PORT" '$1 == "P" && $2 == port { print $9; exit }' "$AGGREGATE")"
        LIMIT_CLIENTS="${LIMIT_CLIENTS:-0}"
        LIMIT_IPS_FILE="$(awk -F '=' '$1 == "LIMIT_IPS_FILE" { print $2; exit }' /etc/default/warp-port-limit)"
        LIMIT_IPS_FILE="${LIMIT_IPS_FILE:-/opt/warp-relay-agent/limited-port-${LIMIT_PORT}-ips.txt}"
        COLLECTED_IPS=0
        if [[ -r "$LIMIT_IPS_FILE" ]]; then
            COLLECTED_IPS="$(awk 'NF { count++ } END { print count + 0 }' "$LIMIT_IPS_FILE")"
        fi
        if systemctl is-active --quiet warp-port-limit-ip-collector.service; then
            IP_HISTORY_STATUS="${GREEN}${COLLECTED_IPS} unique / collector ACTIVE${RESET}"
        else
            IP_HISTORY_STATUS="${RED}${COLLECTED_IPS} unique / collector INACTIVE${RESET}"
        fi
        LIMIT_USAGE="$(awk -v rate="${LIMIT_RATE:-0}" -v mbps="${LIMIT_MBPS:-0}" 'BEGIN {
            percent = 0
            if (mbps > 0) percent = rate * 8 * 100 / (mbps * 1000000)
            printf "%.1f", percent
        }')"
        if tc class show dev "$IFACE" 2>/dev/null | grep -F 'htb 1:fffe ' >/dev/null &&
           iptables -t mangle -S POSTROUTING 2>/dev/null | grep -F "WR_PORT_LIMIT_${LIMIT_PORT}" >/dev/null; then
            LIMIT_COLOR="$GREEN"
            if awk -v usage="$LIMIT_USAGE" 'BEGIN { exit !(usage >= 70) }'; then LIMIT_COLOR="$YELLOW"; fi
            if awk -v usage="$LIMIT_USAGE" 'BEGIN { exit !(usage >= 90) }'; then LIMIT_COLOR="$RED"; fi
            LIMIT_STATUS="${LIMIT_COLOR}OK / ${LIMIT_PORT} / ${LIMIT_MBPS} Mbps / ${LIMIT_USAGE}% / ${LIMIT_CLIENTS} clients${RESET}"
        else
            LIMIT_STATUS="${RED}BROKEN / service active, tc or MARK rule missing${RESET}"
        fi
    fi

    TERMINAL_LINES="$(tput lines 2>/dev/null || printf '40')"
    VISIBLE_TOP="$TOP"
    MAX_VISIBLE=$(( (TERMINAL_LINES - 18) / 2 ))
    (( MAX_VISIBLE < 3 )) && MAX_VISIBLE=3
    (( VISIBLE_TOP > MAX_VISIBLE )) && VISIBLE_TOP="$MAX_VISIBLE"

    printf '\033[H\033[2J'
    printf '%b%s%b  %s  %s\n' "$BOLD$CYAN" "WARP RELAY LIVE" "$RESET" "$(hostname)" "$(date '+%F %T %Z')"
    printf '%s\n' '================================================================================================'
    printf 'Agent: %b   Interface: %s   CF target: %s   Refresh: %ss\n' "$AGENT_STATUS" "$IFACE" "$DST_IP" "$INTERVAL"
    printf 'Port limit: %b\n' "$LIMIT_STATUS"
    if [[ -n "$LIMIT_IPS_FILE" ]]; then
        printf 'IP history: %b   File: %s\n' "$IP_HISTORY_STATUS" "$LIMIT_IPS_FILE"
    fi
    printf '\n%bLIVE TRAFFIC%b\n' "$BOLD" "$RESET"
    printf 'WARP       Down: %11s   Up: %11s   Combined: %11s\n' \
        "$(format_rate "$WARP_RX")" "$(format_rate "$WARP_TX")" "$(format_rate "$WARP_TOTAL")"
    printf 'Interface  RX:   %11s   TX: %11s   Drops: RX %s / TX %s\n' \
        "$(format_rate "$IFACE_RX_RATE")" "$(format_rate "$IFACE_TX_RATE")" "$RX_DROPPED" "$TX_DROPPED"
    printf 'Clients: %s IPs   Sessions: %s total / %s assured / %s unreplied   Conntrack: %s/%s (%s%%)\n' \
        "$CLIENTS_TOTAL" "$SESSIONS" "$ASSURED" "$UNREPLIED" "$CT_COUNT" "$CT_MAX" "$CT_PERCENT"
    printf 'Month %s: Down %s / Up %s / Total %s   Load: %s   RAM: %s\n' \
        "$TRAFFIC_MONTH" "$(format_bytes "$MONTH_RX")" "$(format_bytes "$MONTH_TX")" \
        "$(format_bytes "$(( MONTH_RX + MONTH_TX ))")" "$LOAD_AVERAGE" "$MEMORY"
    printf '\n%bTOP WARP PORTS BY CURRENT BANDWIDTH%b\n' "$BOLD" "$RESET"
    render_table P "$VISIBLE_TOP" "$WARP_TOTAL"
    printf '\n%bTOP CLIENT IPs BY CURRENT BANDWIDTH%b\n' "$BOLD" "$RESET"
    render_table I "$VISIBLE_TOP" "$WARP_TOTAL"
    printf '\n%bq%b quit   Rates use conntrack byte deltas; interface totals include non-WARP traffic.%b' \
        "$YELLOW" "$RESET" "$DIM"
    printf '%b' "$RESET"

    mv -f "$CURRENT" "$PREVIOUS"
    PREVIOUS_RX="$CURRENT_RX"
    PREVIOUS_TX="$CURRENT_TX"
    PREVIOUS_TIME="$CURRENT_TIME"
done
