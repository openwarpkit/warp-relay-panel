#!/bin/bash
# ═══════════════════════════════════════
# WARP Relay Agent — ручное обновление (fallback)
# Используется если API /update недоступен
# Запуск: bash /opt/warp-relay-panel/relay-agent/update.sh
# ═══════════════════════════════════════

set -e

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'; B='\033[1m'

REPO_DIR="/opt/warp-relay-panel"
INSTALL_DIR="/opt/warp-relay-agent"

echo -e "${B}═══ WARP Relay Agent — Manual Update ═══${N}"

# ── Git pull ──
if [ -d "${REPO_DIR}/.git" ]; then
    echo -e "${Y}[1/3] Pulling latest code...${N}"
    cd "$REPO_DIR"
    OLD_HASH=$(git rev-parse --short HEAD)
    git pull --ff-only 2>/dev/null || git pull
    NEW_HASH=$(git rev-parse --short HEAD)
    if [ "$OLD_HASH" = "$NEW_HASH" ]; then
        echo -e "${G}  Already up to date (${OLD_HASH})${N}"
    else
        echo -e "${G}  Updated: ${OLD_HASH} → ${NEW_HASH}${N}"
    fi
else
    echo -e "${R}Git repo not found at ${REPO_DIR}${N}"
    echo -e "Install via: git clone <repo> ${REPO_DIR}"
    exit 1
fi

# ── Копируем файлы ──
echo -e "${Y}[2/3] Updating files...${N}"
cp "${REPO_DIR}/relay-agent/agent.py" "${INSTALL_DIR}/agent.py"
cp "${REPO_DIR}/relay-agent/ensure_rules.sh" "${INSTALL_DIR}/ensure_rules.sh" 2>/dev/null || true
chmod +x "${INSTALL_DIR}/ensure_rules.sh" 2>/dev/null || true

if ! diff -q "${REPO_DIR}/relay-agent/requirements.txt" "${INSTALL_DIR}/requirements.txt" &>/dev/null; then
    echo -e "${Y}  Updating dependencies...${N}"
    cp "${REPO_DIR}/relay-agent/requirements.txt" "${INSTALL_DIR}/requirements.txt"
    ${INSTALL_DIR}/venv/bin/pip install -q -r "${INSTALL_DIR}/requirements.txt"
fi

# ── Restart ──
echo -e "${Y}[3/3] Restarting agent...${N}"
systemctl restart warp-relay-agent
sleep 2

if systemctl is-active --quiet warp-relay-agent; then
    VERSION=$(curl -s http://localhost:${AGENT_PORT:-7580}/health 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('version','?'))" 2>/dev/null || echo "?")
    echo -e "${G}  Agent running (v${VERSION})${N}"
else
    echo -e "${R}  Agent failed! journalctl -u warp-relay-agent --no-pager -n 20${N}"
    exit 1
fi

echo -e "${G}═══ Done ═══${N}"