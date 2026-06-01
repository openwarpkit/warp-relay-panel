# WARP Relay Panel — API Reference (v1.3.0)

Document for integrating with the panel from external projects (bot, frontend, scripts).

## General

- **Base URL panel:** `https://your-project.vercel.app`
- **Auth:** header `X-API-Key: <key>` for all `/api/*` endpoints. Key — env `API_KEY` on Vercel.
- **Content-Type:** `application/json` (where there's a body).
- **Encoding:** UTF-8.
- **Time:** ISO 8601 (`2026-05-15T12:34:56+00:00`). In relay-agent responses — sometimes MSK (`+03:00`).
- **IP:** IPv4 only. IPv6 → error `ipv6_not_supported` or `ipv6_detected`.

### Error Format

Two options depending on error type:

```jsonc
// Structured (bot can parse programmatically):
{ "error": "<error_key>", "detail": "<human readable RU>" }

// Standard FastAPI error (4xx/5xx):
{ "detail": "Invalid API key" }
```

`error_key` values: `client_not_found`, `blocked`, `ip_banned`, `daily_limit` (deprecated, not returned), `invalid_ip`, `ipv6_not_supported`, `warp_detected`, `invalid_token`.

---

## 1. Public endpoints (no X-API-Key)

### `GET /health`
Panel healthcheck.

**Response 200:**
```json
{ "status": "ok", "version": "1.3.0" }
```

---

### `GET /activate/{token}`
Client activation via token-link. Detects client IP (via `x-relay-real-ip` / `X-Real-IP` / `X-Forwarded-For` / `request.client.host`), adds it to relay server whitelists.

**Response:** HTML (for browser display), Status 200/400/403.

**Behavior:**
- **Bot detected** (User-Agent contains `TelegramBot`/`bot`/`crawl`/`curl`/...) → 200 with empty HTML page containing OG-tags.
- **IPv6** → 400 HTML with error `ipv6_detected`.
- **Invalid IP** → 400 HTML.
- **WARP IP** (Cloudflare CIDR or CGNAT 100.64.0.0/10) → 403 HTML "Disable WARP".
- **IP banned** → 403 HTML with ban reason.
- **Invalid token / blocked** → 403 HTML.
- **Success / Already active** → 200 HTML with client IP + rate-limit block (if set).

> Not intended for bots. Bots should use `POST /api/clients/{id}/activate`.

---

## 2. Clients API

### `POST /api/clients`
Create new client and get token for activation link.

**Request body:**
```json
{ "label": "John" }
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `label` | string | no | `""` | Arbitrary client name (for admin UI) |

**Response 200:**
```json
{
  "id": 1,
  "token": "a1b2c3d4e5f67890",
  "label": "John"
}
```

Activation link: `${PANEL_URL}/activate/${token}`.

---

### `GET /api/clients`
List of all clients (with pagination inside — downloads all).

**Query params:**

| Param | Type | Default | Description |
|---|---|---|---|
| `include_blocked` | bool | `true` | Include blocked clients |

**Response 200:** array of client objects.

---

### `GET /api/clients/search`
Search client by IP (current → previous → activation history). Single RPC.

**Query params (required):**

| Param | Type | Default | Description |
|---|---|---|---|
| `ip` | string | — | IPv4 to search |
| `include_log_history` | bool | `true` | Whether to search in activation history |

**Response 200:** array of clients with additional field `match_source` (`"current"` | `"previous"` | `"history"`).

**Errors:**
- 400 `{"detail": "ip required"}` — empty `ip`.

---

### `POST /api/clients/labels`
Batch-resolve `client_id` → `label`. Useful for UI: fetch names for `client_ids` from `/api/traffic` in a single request instead of N `/api/clients/{id}` calls.

**Request body:**
```json
{ "ids": [1, 7, 99] }
```

**Response 200:** mapping `id (string)` → `label (string \| null)`. `null` if client ID doesn't exist.
```json
{
  "1": "John",
  "7": "Peter",
  "99": null
}
```

---

### `GET /api/clients/{client_id}`
Get client by ID.

**Response 200:** client object (same as in list).
**Errors:** 404 `{"detail": "Client not found"}`.

---

### `GET /api/clients/{client_id}/full`
Client + ban flags for current/previous IP + current rate_limit. **1 RPC** (faster than 3 separate queries).

**Response 200:**
```json
{
  "id": 1,
  "token": "a1b2c3d4e5f67890",
  "label": "John",
  "current_ip": "1.2.3.4",
  "previous_ip": "5.6.7.8",
  "last_activated_at": "2026-05-15T10:30:00+00:00",
  "is_blocked": false,
  "created_at": "2026-04-01T12:00:00+00:00",
  "current_ip_banned": false,
  "previous_ip_banned": false,
  "current_ip_shared": false,
  "rate_limit": {
    "mbps": 50.0,
    "expires_at": "2026-05-20T00:00:00+00:00"
  }
}
```

`rate_limit` = `null` if no limit. `expires_at` = `null` for non-expiring limits.

---

### `GET /api/clients/{client_id}/logs`
Client activation history.

**Query params:**
| Param | Type | Default |
|---|---|---|
| `limit` | int | `50` |

---

### `DELETE /api/clients/{client_id}/logs`
Clear all activation history for a client.

**Response 200:** `{ "deleted": 42, "client_id": 1 }`

---

### `GET /api/clients/{client_id}/traffic`
Client traffic from all relays (by their current IP).

**Response 200:**
```json
{
  "client_id": 1,
  "label": "John",
  "ip": "1.2.3.4",
  "relays": {
    "FI-Helsinki": {
      "tx_bytes": 1234567890,
      "rx_bytes": 987654321,
      "total_bytes": 2222222211,
      "tx_human": "1.15 GB",
      "rx_human": "918 MB",
      "total_human": "2.07 GB",
      "clients_on_ip": 1,
      "client_ids": [1],
      "month": "2026-05",
      "updated": "2026-05-15T12:00:00+03:00"
    }
  }
}
```

If `current_ip == null`:
```json
{ "client_id": 1, "label": "John", "ip": null, "relays": {}, "note": "No active IP" }
```

---

### `POST /api/clients/{client_id}/activate`
**Manual activation by IP** (called by bot). Saves IP to `current_ip`, syncs whitelist.

**Request body:**
```json
{ "ip": "1.2.3.4" }
```

**Response 200 (success):**
```json
{
  "status": "activated",
  "client_id": 1,
  "ip": "1.2.3.4",
  "old_ip": "5.6.7.8",
  "rate_limit": { "mbps": 50.0, "expires_at": null },
  "relay_sync": {
    "FI-Helsinki": { "ok": true, "added": "1.2.3.4", "removed": "5.6.7.8", "refcount": 1 }
  }
}
```

**Response 200 (already active):**
```json
{
  "status": "already_active",
  "client_id": 1,
  "ip": "1.2.3.4",
  "rate_limit": null
}
```

**Response 200 (error — JSON, not HTTPException):**
```json
{
  "error": "warp_detected",
  "detail": "Обнаружен Cloudflare WARP / VPN. Отключите WARP и повторите активацию"
}
```

---

### `PATCH /api/clients/{client_id}/block`
Block/unblock client. If blocking and IP is not shared — removes from relay whitelists.

**Request body:** `{ "blocked": true }`

**Response 200:** client object + flags (same as `/full`).

**Errors:** 404 if client doesn't exist.

---

### `DELETE /api/clients/{client_id}`
Delete client. Also deletes their entire activation history (CASCADE) and removes IP from relay whitelists (if not shared).

**Response 200:** `{ "deleted": true, "id": 1 }`.

**Errors:** 404 if client doesn't exist.

---

## 3. IP Blacklist

### `POST /api/blacklist`
Ban IP. Removes it from all relays (if active).

**Request body:** `{ "ip": "1.2.3.4", "reason": "abuse" }`

**Response 200:**
```json
{
  "id": 7,
  "ip": "1.2.3.4",
  "reason": "abuse",
  "already_exists": false
}
```

`already_exists: true` means IP was already banned (RPC idempotent).

---

### `GET /api/blacklist`
List bans. Two modes:

**No pagination (no `page` param):** array of all records.

**With pagination:** `?page=0&per_page=20&search=1.2.3.4`.

---

### `GET /api/blacklist/check/{ip}`
Check if IP is banned.

**Response 200 (banned):** `{ "banned": true, "id": 7, "ip": "1.2.3.4", "reason": "abuse", "created_at": "..." }`

**Response 200 (not banned):** `{ "banned": false, "ip": "1.2.3.4" }`

---

### `GET /api/blacklist/{ban_id}`
Ban details by ID.

---

### `DELETE /api/blacklist/{ban_id}`
Unban by ID.

**Response 200:** `{ "deleted": true, "id": 7 }`.

---

### `DELETE /api/blacklist/by-ip`
Unban by IP (alternative).

**Request body:** `{ "ip": "1.2.3.4" }`

---

## 4. Relays

### `POST /api/relays`
Register relay server in panel.

**Request body:**
```json
{
  "name": "FI-Helsinki",
  "host": "1.2.3.4",
  "agent_port": 7580,
  "agent_secret": "secret",
  "agent_type": "full"
}
```

| Field | Type | Required | Default |
|---|---|---|---|
| `name` | string | yes | — |
| `host` | string | yes | IPv4 or DNS of relay |
| `agent_port` | int | no | `7580` |
| `agent_secret` | string | no | `""` |
| `agent_type` | string | no | `"full"` |

**Response 200:** relay object from DB.

---

### `GET /api/relays`
List of relays.

**Query:**
`?fields=basic` — without `last_health` (lighter payload).

---

### `DELETE /api/relays/{relay_id}`
Delete relay from panel (agent on server stays running, just stops syncing).

---

### `PATCH /api/relays/{relay_id}/toggle`
Enable/disable relay (without deleting).

**Request body:** `{ "active": false }`

---

### `GET /api/relays/{relay_id}/health`
Proxy to agent's `GET /health` (with advanced diagnostics).

---

### `GET /api/relays/{relay_id}/stats`
Proxy to agent's `GET /stats`.

---

### `GET /api/relays/{relay_id}/traffic`
Proxy to agent's `GET /traffic`.

**Query:**
`?summary=true` | `?top=10`

---

### `POST /api/relays/{relay_id}/sync`
Sync whitelist to specific relay (background operation).

---

### `POST /api/relays/sync-all`
Sync all full-relays concurrently.

---

### `GET /api/relays/health-all`
Health-check all relays concurrently.

---

### `POST /api/relays/{relay_id}/update`
Trigger `/update` on agent (fire-and-forget, ~100ms response).

**Response 200:**
```json
{
  "relay": "FI-Helsinki",
  "accepted": true,
  "message": "Update started in background",
  "check_status": "GET /health → last_update"
}
```

Check result: `GET /api/relays/{id}/health` → `last_update`.

---

### `POST /api/relays/update-all`
Same for all relays.

---

### `GET /api/relays/{relay_id}/whitelist-payload`
**Internal endpoint** for startup-resync agent. Returns full payload with decrypted client IPs and all active rate_limits.

---

## 5. Rate-limits

### `POST /api/rate-limits`
Set rate-limit for IP. Applied to all full-relays (push to agents + DB save).

**Request body:**
```json
{
  "ip": "1.2.3.4",
  "mbps": 50.0,
  "expires_in_seconds": 3600,
  "reason": "fair-use",
  "client_id": 1
}
```

---

### `GET /api/rate-limits`
List all rate-limits.

---

### `GET /api/rate-limits/expired`
Expired limits — for external cleanup scheduler.

---

### `GET /api/rate-limits/{ip}`
Get limit for IP.

---

### `DELETE /api/rate-limits/{ip}`
Remove limit.

---

### `DELETE /api/rate-limits/by-ip`
Remove limit via body (alternative): `{ "ip": "1.2.3.4" }`

---

## 6. Stats / Dashboard / Traffic

### `GET /api/stats`
Light aggregated statistics (single RPC `dashboard_stats`).

---

### `GET /api/traffic`
Traffic from all relays (by IP).

---

### `GET /api/dashboard`
Main screen: relays(basic) + stats.

---

### `GET /activate/{token}`
Activation via link (public, HTML).

---

### `GET /health`
Healthcheck.

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

Endpoints `/whitelist/*` and `/rate-limit*` on the min-agent return `200 OK stub` (`{agent_type:"min", skipped:true}`) — the panel doesn't call them itself (filtered by `agent_type='full'`), but the stub protects against errors.
