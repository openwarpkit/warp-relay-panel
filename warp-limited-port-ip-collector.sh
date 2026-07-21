#!/usr/bin/env bash
set -Eeuo pipefail

PORT="${1:?Usage: $0 PORT}"
INTERVAL="${COLLECT_INTERVAL:-5}"
RECIPE="${RECIPE:-/opt/warp-relay-agent/rules_recipe.json}"

[[ "$EUID" -eq 0 ]] || { echo "Run as root"; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "Invalid port"; exit 1; }
PORT=$((10#$PORT))
(( PORT >= 1 && PORT <= 65535 )) || { echo "Invalid port"; exit 1; }
[[ "$INTERVAL" =~ ^[0-9]+$ ]] && (( INTERVAL >= 1 )) || {
    echo "COLLECT_INTERVAL must be a positive integer"
    exit 1
}
[[ -f "$RECIPE" ]] || { echo "Recipe not found: $RECIPE"; exit 1; }

for command_name in awk cmp conntrack jq mktemp sort; do
    command -v "$command_name" >/dev/null || {
        echo "Required command not found: $command_name"
        exit 1
    }
done

DST_IP="$(jq -r '.dst_ip // empty' "$RECIPE")"
jq -e --argjson port "$PORT" '.ports | index($port) != null' \
    "$RECIPE" >/dev/null || {
    echo "Port $PORT is not configured as a WARP relay port"
    exit 1
}

OUTPUT="${LIMIT_IPS_FILE:-/opt/warp-relay-agent/limited-port-${PORT}-ips.txt}"
[[ "$OUTPUT" == /* ]] || { echo "LIMIT_IPS_FILE must be absolute"; exit 1; }
OUTPUT_DIR="${OUTPUT%/*}"
mkdir -p "$OUTPUT_DIR"
touch "$OUTPUT"
chmod 0600 "$OUTPUT"

TMP_FILE=""

cleanup() {
    if [[ -n "$TMP_FILE" && -f "$TMP_FILE" ]]; then
        rm -f "$TMP_FILE"
    fi
}

trap cleanup EXIT
trap 'exit 0' INT TERM HUP

snapshot_ips() {
    conntrack -L -p udp -o extended 2>/dev/null |
        awk -v target="$DST_IP" -v port="$PORT" '
            {
                tuple = 0
                source = replySource = destinationPort = ""
                for (i = 1; i <= NF; i++) {
                    split($i, pair, "=")
                    if (pair[1] == "src") {
                        tuple++
                        if (tuple == 1) source = pair[2]
                        if (tuple == 2) replySource = pair[2]
                    } else if (tuple == 1 && pair[1] == "dport") {
                        destinationPort = pair[2]
                    }
                }
                if (replySource == target && destinationPort == port && source != "") {
                    seen[source] = 1
                }
            }
            END {
                for (ip in seen) print ip
            }
        ' || true
}

LAST_COUNT=-1
while true; do
    TMP_FILE="$(mktemp "${OUTPUT}.tmp.XXXXXX")"
    {
        cat "$OUTPUT"
        snapshot_ips
    } | LC_ALL=C sort -u > "$TMP_FILE"
    chmod 0600 "$TMP_FILE"

    if cmp -s "$OUTPUT" "$TMP_FILE"; then
        rm -f "$TMP_FILE"
    else
        mv -f "$TMP_FILE" "$OUTPUT"
    fi
    TMP_FILE=""

    COUNT="$(awk 'NF { count++ } END { print count + 0 }' "$OUTPUT")"
    if [[ "$COUNT" != "$LAST_COUNT" ]]; then
        echo "Limited port $PORT: $COUNT unique IPs in $OUTPUT"
        LAST_COUNT="$COUNT"
    fi
    sleep "$INTERVAL"
done
