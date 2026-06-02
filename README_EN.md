# WARP Relay Panel v1.3.0

Control panel for whitelist and rate-limits of WARP Relay servers.
Free hosting of API panel (Docker/FastAPI + Supabase), native Go agent v2.1.0+ on relays.

---

## Architecture

```
Telegram Bot  ──HTTP──▶  Docker (FastAPI)  ──HTTP──▶  Relay Agent 1 (full)
                         Supabase (PostgreSQL)  ────▶  Relay Agent 2 (full)
                              ▲                 ────▶  Relay Agent N (min)
                              │
                       Client via link
                       (identified by IPv4)
```

| Component | Where | Cost |
|-----------|-----|-----------|
| API Panel | Docker container | Your VPS / Serverless |
| Database | Supabase PostgreSQL | Free (500 MB) |
| Relay Agent (Go) | On each relay server (~7 MB binary) | VPS |
| Telegram Bot | Server | VPS |

**Two types of relay agents:**

- **`full`** — whitelist via `ipset` + individual rate-limits upon panel request. Used for subscribers.
- **`min`** — no whitelist, allows everyone. Imposes a shared limit of N Mbps (default 25) per active client IP. Used for free/public relays.

---

## Quick Start

### 1. Panel (Docker + Supabase) — 5 minutes

**Supabase:**
1. Create a project at [supabase.com](https://supabase.com).
2. **SQL Editor** → paste [supabase_schema.sql](supabase_schema.sql) → Run. The script is idempotent — safe to run multiple times.
3. Copy **Project URL** and **service_role key**.

**Docker — local run:**

```bash
docker build -t warp-relay-panel .
docker run -d -p 8000:8000 --env-file .env warp-relay-panel
```

After building, set the environment variables in `.env`:

| Variable | Value |
|------------|----------|
| `SUPABASE_URL` | `https://xxx.supabase.co` |
| `SUPABASE_KEY` | `eyJ...service-role-key...` |
| `ENCRYPTION_KEY` | Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `API_KEY` | Any secret key for the bot |
| `AGENT_SECRET` | Shared secret for relay agents |

→ **Redeploy** to apply variables.

### 2. Relay Server — 1 command

Binaries come from GitHub Releases — nothing is built on the VPS:

```bash
ssh root@RELAY_IP

git clone https://github.com/nellimonix/warp-relay-panel.git /opt/warp-relay-panel
sudo bash /opt/warp-relay-panel/relay-agent/deploy/setup.sh        # full
# or
sudo bash /opt/warp-relay-panel/relay-agent/deploy/setup-min.sh    # min
```

The script will ask for the `Agent secret` (same as `AGENT_SECRET` in the panel configuration) and port (default 7580). It downloads the fresh binary from [releases/latest](https://github.com/nellimonix/warp-relay-panel/releases/latest), configures iptables/ipset/tc, creates a systemd unit, and enables auto-restore of rules on reboot.

Override owner/repo for fork: `AGENT_RELEASE_REPO=user/repo bash setup.sh`.

### 3. Add relay to panel

```bash
PANEL="http://your-panel-ip:8000"
KEY="your-api-key"

# Full-relay
curl -X POST ${PANEL}/api/relays \
  -H "X-API-Key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "FI-Helsinki", "host": "1.2.3.4", "agent_port": 7580, "agent_secret": "...", "agent_type": "full"}'

# Min-relay
curl -X POST ${PANEL}/api/relays \
  -H "X-API-Key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Free-1", "host": "5.6.7.8", "agent_port": 7580, "agent_secret": "...", "agent_type": "min"}'
```

### 4. Create a client

```bash
curl -X POST ${PANEL}/api/clients \
  -H "X-API-Key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d '{"label": "John"}'

# Response: {"id": 1, "token": "a1b2c3d4e5f67890", ...}
# Link: http://your-panel-ip:8000/activate/a1b2c3d4e5f67890
```

### 5. Synchronization

```bash
curl -X POST ${PANEL}/api/relays/sync-all -H "X-API-Key: ${KEY}"
```

---

## Updating Relay Servers

**Release-driven flow:** agent is NOT built on the VPS. CI builds binaries on git tag creation, agent downloads the fresh binary from GitHub Releases.

```bash
# Update all relays (fire-and-forget):
curl -X POST ${PANEL}/api/relays/update-all -H "X-API-Key: ${KEY}"

# Update one:
curl -X POST ${PANEL}/api/relays/{id}/update -H "X-API-Key: ${KEY}"
```

What happens on the agent during `/update`:
1. `git pull` (for scripts/configs in `/opt/warp-relay-panel`).
2. GitHub API → check `tag_name` of latest release.
3. If newer — download `warp-relay-agent` (or `-min`) from release assets.
4. Atomic swap of binary + `systemctl restart`.

Time: ~10-30 seconds. Load on VPS: ~7 MB download.

Check result via `/health` of each relay:
```bash
curl -X GET ${PANEL}/api/relays/{id}/health -H "X-API-Key: ${KEY}"
# → "last_update": {"ok": true, "release_tag": "agent-v2.2.0", "finished_at": "..."}
```

### Creating a new agent release

```bash
git tag agent-v2.2.0
git push origin agent-v2.2.0
```

Workflow [.github/workflows/release-agent.yml](.github/workflows/release-agent.yml) builds `warp-relay-agent`, `warp-relay-agent-min`, `*-arm64` and attaches to the Release.

### Auto-restore on Reboot

On every start, the agent (via `ExecStartPre`) checks and restores ipset + iptables rules from saved configs (`rules_recipe.json`).

---

## Security

### ENCRYPTION_KEY — critical

`ENCRYPTION_KEY` is used to encrypt client IPs in the database (Fernet AES-128-CBC).

> **⚠️ If `ENCRYPTION_KEY` is changed — all previously encrypted IPs become unreadable.** Clients will show up with a `decrypt_error` error, activations will continue to work (new IPs with the new key), but history will be lost.

**Rules:**
- Generate once: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- Store in a safe place (password manager).
- Never change after starting work with clients.
- Do not commit to git.

### Relay Agent

Agent listens on port 7580 via HTTP. Protection:

```bash
# If there's a fixed panel IP:
ufw allow from PANEL_IP to any port 7580
ufw deny 7580
```

For enhanced security, requests are protected via `AGENT_SECRET` (`X-Agent-Key` header).

### Database Encryption

All IPs are stored encrypted (Fernet). SHA-256 hash is used for searching. The IP ban list is also encrypted. Even with a database leak, IPs are not revealed.

---

## Panel API

All `/api/*` endpoints require the `X-API-Key` header.

### Clients

| Method | Path | Description |
|-------|------|----------|
| `POST` | `/api/clients` | Create `{"label":"..."}` |
| `GET` | `/api/clients` | List all (`?include_blocked=false`) |
| `GET` | `/api/clients/search?ip=1.2.3.4` | Search by current/previous IP + activation history |
| `GET` | `/api/clients/{id}` | Client details |
| `GET` | `/api/clients/{id}/full` | Client + ban flags + current rate-limit (1 RPC) |
| `POST` | `/api/clients/{id}/activate` | Manual activation by IP `{"ip":"1.2.3.4"}` (for bot) |
| `GET` | `/api/clients/{id}/logs` | Activation history (`?limit=50`) |
| `DELETE` | `/api/clients/{id}/logs` | Clear activation history |
| `GET` | `/api/clients/{id}/traffic` | Client traffic from all relays |
| `PATCH` | `/api/clients/{id}/block` | Block `{"blocked": true}` |
| `DELETE` | `/api/clients/{id}` | Delete (+ remove IP from relays) |

> **Shared IP:** when blocking/deleting a client, the IP is removed from relays only if no one else is on that IP (refcount).

### Relay Servers

| Method | Path | Description |
|-------|------|----------|
| `POST` | `/api/relays` | Add `{name, host, agent_port, agent_secret, agent_type:"full"\|"min"}` |
| `GET` | `/api/relays` | List (`?fields=basic` — without last_health) |
| `DELETE` | `/api/relays/{id}` | Delete |
| `PATCH` | `/api/relays/{id}/toggle` | Turn on/off `{"active": false}` |
| `GET` | `/api/relays/{id}/health` | Health + `last_update` |
| `GET` | `/api/relays/{id}/stats` | Statistics (clients, traffic, ports) |
| `GET` | `/api/relays/{id}/traffic` | Traffic by IP (`?summary=true`, `?top=10`) |
| `POST` | `/api/relays/{id}/sync` | Sync whitelist (full only) |
| `POST` | `/api/relays/{id}/update` | Update agent (fire-and-forget) |
| `GET` | `/api/relays/{id}/whitelist-payload` | Full payload for startup-resync (internal) |
| `POST` | `/api/relays/sync-all` | Sync all full-relays |
| `POST` | `/api/relays/update-all` | Update all relays |
| `GET` | `/api/relays/health-all` | Check all relays |

### IP Blacklist (hard-ban)

| Method | Path | Description |
|-------|------|----------|
| `POST` | `/api/blacklist` | Ban `{"ip":"1.2.3.4", "reason":"..."}` |
| `GET` | `/api/blacklist` | List (`?page=0&per_page=20&search=1.2.3.4`) |
| `GET` | `/api/blacklist/check/{ip}` | Check IP |
| `GET` | `/api/blacklist/{id}` | Ban details |
| `DELETE` | `/api/blacklist/{id}` | Unban by ID |
| `DELETE` | `/api/blacklist/by-ip` | Unban `{"ip":"1.2.3.4"}` |

> **IP-ban** blocks activation for ANY client with this IP. Clients are not blocked — they can activate from a different IP.

### Rate-limits (per-IP, in Mbps)

| Method | Path | Description |
|-------|------|----------|
| `POST` | `/api/rate-limits` | Set `{"ip","mbps","expires_in_seconds"?,"reason"?,"client_id"?}` |
| `GET` | `/api/rate-limits` | List all |
| `GET` | `/api/rate-limits/expired` | Expired (for external cleanup scheduler) |
| `GET` | `/api/rate-limits/{ip}` | Get limit for IP |
| `DELETE` | `/api/rate-limits/{ip}` | Remove limit |
| `DELETE` | `/api/rate-limits/by-ip` | Remove `{"ip":"..."}` (alternative) |

> Rate-limits apply only on full-relays (via CONNMARK + HTB). On min-relays — shared limit.

### Traffic / Stats / Activation

| Method | Path | Description |
|-------|------|----------|
| `GET` | `/api/traffic` | Traffic from all relays (by IP) |
| `GET` | `/api/stats` | Light statistics via RPC `dashboard_stats` |
| `GET` | `/api/dashboard` | Main screen: relays(basic) + stats |
| `GET` | `/activate/{token}` | Activation by link (public, HTML) |
| `GET` | `/health` | Healthcheck |

---

## Relay Agent API

Port 7580. All endpoints (except `/health`) require `X-Agent-Key`.

### Full-agent

| Method | Path | Description |
|-------|------|----------|
| `POST` | `/whitelist/update` | `{"new_ip":"...", "old_ip":"...", "client_id": 1}` |
| `POST` | `/whitelist/remove` | `{"ip":"..."}` |
| `POST` | `/whitelist/sync` | `{"clients":[{"ip","client_id"}]}` (background rebuild) |
| `GET` | `/whitelist/list` | Current ipset |
| `POST` | `/rate-limit` | `{"ip","mbps","expires_at"?,"client_id"?}` |
| `DELETE` | `/rate-limit/{ip}` | Remove limit |
| `GET` | `/rate-limit/{ip}` | Get limit |
| `GET` | `/rate-limits` | List all limits |
| `GET` | `/traffic` | Traffic by IP for the month (reset on MSK) |
| `GET` | `/traffic/{ip}` | Specific IP + `clients_on_ip` |
| `POST` | `/traffic/reset` | Forced reset |
| `GET` | `/stats` | Clients, ports, sessions, traffic |
| `GET` | `/refcount` | Mapping IP → client_ids |
| `GET` | `/health` | System status + `last_update` (no auth) |
| `POST` | `/update` | Self-update via GitHub Releases (fire-and-forget) |

### Min-agent

Same `/health`, `/stats`, `/traffic*`, `/update` + specific ones:

| Method | Path | Description |
|-------|------|----------|
| `GET` | `/shaped` | IP under shared-limit + classid + lastSeen |
| `POST` | `/shaped/reset` | Remove all shared-limits (reconcile will reapply) |

Endpoints `/whitelist/*` and `/rate-limit*` on the min-agent return `200 OK stub` (`{agent_type:"min", skipped:true}`) — the panel doesn't call them itself (filter by `agent_type='full'`), but the stub protects against errors.

## Testing (Fuzzing, Benchmarks, API)

The project includes several levels of automated testing to ensure performance and security.

### Go-agent (Unit, Fuzzing, Benchmarks)

Agent tests are located in the `relay-agent` directory.

```bash
cd relay-agent

# Run standard unit tests
make test

# Run Fuzz tests (validating robustness against corrupted state files on disk)
# Runs FuzzRefcountLoad, FuzzRatelimitLoad, and FuzzTrafficLoad
# You can change FUZZTIME (default is 10s)
make test-fuzz FUZZTIME=5s

# Run Benchmarks (checking high performance and zero-allocations in hot paths)
make test-bench
```

### FastAPI Panel (Integration Tests)

The foundation of integration tests for the API panel uses `TestClient` and mock database stubs (no need to spin up a real PostgreSQL instance).

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt pytest respx pytest-asyncio
pytest api/tests/
```

---

## Telegram Bot Integration

<details>
<summary><b>Example for aiogram 3</b></summary>

```python
import aiohttp

PANEL_URL = "http://your-panel-ip:8000"
API_KEY = "your-api-key"
HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}

async def create_client(label: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{PANEL_URL}/api/clients",
            headers=HEADERS,
            json={"label": label},
        ) as resp:
            return await resp.json()

async def get_activate_url(token: str) -> str:
    return f"{PANEL_URL}/activate/{token}"

async def get_client_info(client_id: int) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{PANEL_URL}/api/clients/{client_id}/full",
            headers=HEADERS,
        ) as resp:
            return await resp.json()

async def manual_activate(client_id: int, ip: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{PANEL_URL}/api/clients/{client_id}/activate",
            headers=HEADERS,
            json={"ip": ip},
        ) as resp:
            return await resp.json()

async def ban_ip(ip: str, reason: str = "") -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{PANEL_URL}/api/blacklist",
            headers=HEADERS,
            json={"ip": ip, "reason": reason},
        ) as resp:
            return await resp.json()

async def set_rate_limit(ip: str, mbps: float, ttl_seconds: int | None = None) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{PANEL_URL}/api/rate-limits",
            headers=HEADERS,
            json={"ip": ip, "mbps": mbps, "expires_in_seconds": ttl_seconds},
        ) as resp:
            return await resp.json()
```

</details>

---

## Project Structure

```
warp-relay-panel/
├── api/                              # Panel backend (Python FastAPI)
│   ├── index.py                      # FastAPI (routes, activation, blacklist, rate-limits)
│   ├── database.py                   # Supabase ops (atomic RPCs)
│   ├── relay_client.py               # HTTP-client to relay agents
│   ├── crypto.py                     # IP encryption (Fernet)
│   └── cache.py                      # In-memory TTL cache
├── relay-agent/                      # Go-agent (installed on each relay)
│   ├── cmd/agent/                    # full-agent
│   ├── cmd/agent-min/                # min-agent
│   ├── internal/                     # modules (server, selfupdate, ratelimit, ...)
│   ├── deploy/
│   │   ├── setup.sh                  # setup full
│   │   ├── setup-min.sh              # setup min
│   │   ├── ensure_rules.sh           # restore iptables/ipset (full)
│   │   ├── ensure_rules_min.sh       # restore for min
│   │   ├── warp-relay-agent.service
│   │   └── warp-relay-agent-min.service
│   ├── go.mod / go.sum
│   ├── Makefile
│   └── README.md
├── .github/workflows/
│   ├── release-agent.yml             # build & release binaries on tag agent-v*
│   └── docker-build.yml
├── supabase_schema.sql               # SQL to create tables + RPC (source of truth)
├── requirements.txt                  # Python deps
└── .env.example                      # Environment variables
```

---

## Changelog

### v1.3.0 (current)
- **Release-flow via GitHub Actions:** agent binaries are built by CI and attached to the release upon creating an `agent-v*` tag. Nothing is compiled on the VPS anymore.
- **Self-update download-driven:** agent on `/update` downloads fresh binary from GitHub Releases (~10-30 sec) instead of `make build` (~180 sec).
- Removed old Python relay-agent (completely on Go v2.1.0+).
- Removed deprecated DB fields: `clients.note`, `clients.activations_today`, `clients.activations_reset_date`, `activation_log.user_agent`.
- Removed daily activation limit (`MAX_ACTIVATIONS_PER_DAY`).
- All migrations collapsed into a single `supabase_schema.sql` (source of truth), including RPCs.

### v2.1.0 — Go-agent
- Full rewrite of relay-agent from Python to Go (single static binary ~7 MB).
- Native netlink on hot paths (`conntrack`, `ipset`) — sharp drop in CPU.
- NAT rules management + per-IP rate-limit via CONNMARK + HTB.
- Support for two agent types: `full` (whitelist + per-IP rate-limit) and `min` (no whitelist, shared limit per active IP).
- prebuilt-binaries (now live in GitHub Releases, not in the repo).

### v1.2.2
- Background whitelist sync via `/whitelist/sync`.
- Last sync status in `/health` → `last_sync`.
- Pagination for Supabase fetches.
- Fixed removing orphaned IPs from ipset.

### v1.2.1
- Relay updates via API (fire-and-forget).
- Last update status in `/health` → `last_update`.
- MSK Timezone on all relays (traffic resets on Moscow time).

### v1.2.0
- IP-blacklist (hard-ban by IP).
- Shared IP protection (refcount on panel and agent).
- IP traffic monitoring (conntrack accounting).
- Bot filtering (Telegram preview, etc.).
- Auto-restore iptables/ipset on reboot.

### v1.0.0
- Initial release.
