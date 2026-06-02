# WARP Relay Panel — API Reference (v1.3.0)

Документ для интеграции с панелью из внешних проектов (бот, фронтенд, скрипты).

## Общее

- **Base URL панели:** `http://your-panel-ip:8000`
- **Auth:** заголовок `X-API-Key: <ключ>` для всех `/api/*` endpoints. Ключ задается в `.env`.
- **Content-Type:** `application/json` (где есть body).
- **Encoding:** UTF-8.
- **Время:** ISO 8601 (`2026-05-15T12:34:56+00:00`). В ответах relay-агентов — иногда МСК (`+03:00`).
- **IP:** только IPv4. IPv6 → ошибка `ipv6_not_supported` или `ipv6_detected`.

### Формат ошибок

Два варианта в зависимости от типа ошибки:

```jsonc
// Структурированная (бот может разобрать программно):
{ "error": "<error_key>", "detail": "<human readable RU>" }

// Стандартная FastAPI ошибка (4xx/5xx):
{ "detail": "Invalid API key" }
```

`error_key` значения: `client_not_found`, `blocked`, `ip_banned`, `daily_limit` (deprecated, не возвращается), `invalid_ip`, `ipv6_not_supported`, `warp_detected`, `invalid_token`.

---

## 1. Публичные endpoints (без X-API-Key)

### `GET /health`
Healthcheck панели.

**Response 200:**
```json
{ "status": "ok", "version": "1.3.0" }
```

---

### `GET /activate/{token}`
Активация клиента по токен-ссылке. Определяет IP клиента (через `x-relay-real-ip` / `X-Real-IP` / `X-Forwarded-For` / `request.client.host`), записывает его на whitelist relay-серверов.

**Response:** HTML (для отображения в браузере), Status 200/400/403.

**Поведение:**
- **Bot detected** (User-Agent содержит `TelegramBot`/`bot`/`crawl`/`curl`/...) → 200 с пустой HTML-страницей с OG-тегами.
- **IPv6** → 400 HTML с ошибкой `ipv6_detected`.
- **Invalid IP** → 400 HTML.
- **WARP IP** (Cloudflare CIDR или CGNAT 100.64.0.0/10) → 403 HTML "Отключите WARP".
- **IP banned** → 403 HTML с причиной бана.
- **Invalid token / blocked** → 403 HTML.
- **Success / Already active** → 200 HTML с IP клиента + блок с rate-limit (если задан).

> Для бота этот endpoint не предназначен. Бот вызывает `POST /api/clients/{id}/activate`.

---

## 2. Clients API

### `POST /api/clients`
Создать нового клиента и получить токен для ссылки активации.

**Request body:**
```json
{ "label": "Иван" }
```

| Поле | Тип | Обязат. | Default | Описание |
|---|---|---|---|---|
| `label` | string | нет | `""` | Произвольное имя клиента (для админки) |

**Response 200:**
```json
{
  "id": 1,
  "token": "a1b2c3d4e5f67890",
  "label": "Иван"
}
```

Ссылка активации: `${PANEL_URL}/activate/${token}`.

---

### `GET /api/clients`
Список клиентов с пагинацией.

**Query params:**

| Param | Тип | Default | Описание |
|---|---|---|---|
| `include_blocked` | bool | `true` | Включать заблокированных |
| `page` | int | `0` | Номер страницы |
| `per_page` | int | `50` | Размер страницы |

**Response 200:** объект с пагинацией:
```json
{
  "items": [
    {
      "id": 1,
      "token": "a1b2c3d4e5f67890",
      "label": "Иван",
      "current_ip": "1.2.3.4",
      "previous_ip": "5.6.7.8",
      "last_activated_at": "2026-05-15T10:30:00+00:00",
      "is_blocked": false,
      "created_at": "2026-04-01T12:00:00+00:00"
    }
  ],
  "total": 150,
  "page": 0,
  "per_page": 50,
  "total_pages": 3
}
```

`current_ip` / `previous_ip` могут быть `null` или `"decrypt_error"` (если ENCRYPTION_KEY менялся).

---

### `GET /api/clients/search`
Поиск клиента по IP (current → previous → история активаций). Один RPC.

**Query params (обязательные):**

| Param | Тип | Default | Описание |
|---|---|---|---|
| `ip` | string | — | IPv4 для поиска |
| `include_log_history` | bool | `true` | Искать ли в истории активаций |

**Response 200:** массив клиентов с дополнительным полем `match_source`:
```json
[
  {
    "id": 1,
    "token": "a1b2c3d4e5f67890",
    "label": "Иван",
    "current_ip": "1.2.3.4",
    "previous_ip": null,
    "last_activated_at": "2026-05-15T10:30:00+00:00",
    "is_blocked": false,
    "created_at": "2026-04-01T12:00:00+00:00",
    "match_source": "current"
  }
]
```

`match_source`: `"current"` | `"previous"` | `"history"`.

**Errors:**
- 400 `{"detail": "ip required"}` — пустой `ip`.

---

### `POST /api/clients/labels`
Batch-резолв `client_id` → `label`. Полезно для UI: по `client_ids` из `/api/traffic` показать имена клиентов одним запросом вместо N штук `/api/clients/{id}`.

**Request body:**
```json
{ "ids": [1, 7, 99] }
```

| Поле | Тип | Обязат. | Описание |
|---|---|---|---|
| `ids` | int[] | да | Список client_id |

**Response 200:** маппинг `id (string)` → `label (string \| null)`. `null` если клиента с таким ID нет.
```json
{
  "1": "Иван",
  "7": "Пётр",
  "99": null
}
```

---

### `GET /api/clients/{client_id}`
Получить клиента по ID.

**Response 200:** объект клиента (как в списке).
**Errors:** 404 `{"detail": "Client not found"}`.

---

### `GET /api/clients/{client_id}/full`
Клиент + флаги бана current/previous IP + текущий rate_limit. **1 RPC** (быстрее чем 3 отдельных запроса).

**Response 200:**
```json
{
  "id": 1,
  "token": "a1b2c3d4e5f67890",
  "label": "Иван",
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

`rate_limit` = `null`, если лимита нет. `expires_at` = `null` для бессрочных.

---

### `GET /api/clients/{client_id}/logs`
История активаций клиента.

**Query params:**

| Param | Тип | Default |
|---|---|---|
| `limit` | int | `50` |

**Response 200:**
```json
{
  "client_id": 1,
  "label": "Иван",
  "logs": [
    {
      "id": 100,
      "ip": "1.2.3.4",
      "created_at": "2026-05-15T10:30:00+00:00"
    }
  ]
}
```

---

### `DELETE /api/clients/{client_id}/logs`
Очистить всю историю активаций клиента.

**Response 200:**
```json
{ "deleted": 42, "client_id": 1 }
```

---

### `GET /api/clients/{client_id}/traffic`
Трафик клиента со всех relay (по его текущему IP).

**Response 200:**
```json
{
  "client_id": 1,
  "label": "Иван",
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

Если `current_ip == null`:
```json
{ "client_id": 1, "label": "Иван", "ip": null, "relays": {}, "note": "No active IP" }
```

---

### `POST /api/clients/{client_id}/activate`
**Ручная активация по IP** (вызывается ботом). Записывает IP в `current_ip`, синхронизирует whitelist.

**Request body:**
```json
{ "ip": "1.2.3.4" }
```

| Поле | Тип | Обязат. | Описание |
|---|---|---|---|
| `ip` | string | да | IPv4-адрес клиента |

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

**Response 200 (error — JSON, не HTTPException):**
```json
{
  "error": "warp_detected",
  "detail": "Обнаружен Cloudflare WARP / VPN. Отключите WARP и повторите активацию"
}
```

Возможные `error`: `client_not_found`, `blocked`, `ip_banned` (с `detail` "...: <reason>"), `invalid_ip`, `ipv6_not_supported`, `warp_detected`.

---

### `PATCH /api/clients/{client_id}/block`
Заблокировать/разблокировать клиента. Если блокируем и IP не общий — снимаем с whitelist relay.

**Request body:**
```json
{ "blocked": true }
```

**Response 200:** объект клиента + флаги (как в `/full`):
```json
{
  "id": 1,
  "token": "...",
  "label": "Иван",
  "current_ip": "1.2.3.4",
  "previous_ip": "5.6.7.8",
  "last_activated_at": "...",
  "is_blocked": true,
  "created_at": "...",
  "current_ip_banned": false,
  "previous_ip_banned": false,
  "current_ip_shared": false,
  "rate_limit": null
}
```

**Errors:** 404 если клиента нет.

---

### `DELETE /api/clients/{client_id}`
Удалить клиента. Удаляет также всю его историю активаций (CASCADE) и снимает IP с whitelist relay (если не общий).

**Response 200:**
```json
{ "deleted": true, "id": 1 }
```

**Errors:** 404 если клиента нет.

---

## 3. IP Blacklist

### `POST /api/blacklist`
Забанить IP. Снимает его со всех relay'ев (если был активен).

**Request body:**
```json
{ "ip": "1.2.3.4", "reason": "abuse" }
```

| Поле | Тип | Обязат. | Default |
|---|---|---|---|
| `ip` | string | да | — |
| `reason` | string | нет | `""` |

**Response 200:**
```json
{
  "id": 7,
  "ip": "1.2.3.4",
  "reason": "abuse",
  "already_exists": false
}
```

`already_exists: true` означает что IP уже был забанен (RPC идемпотентный).

---

### `GET /api/blacklist`
Список банов. Два режима:

**Без пагинации (`page` не задан):** массив всех записей.
```json
[
  { "id": 7, "ip": "1.2.3.4", "reason": "abuse", "created_at": "..." }
]
```

**С пагинацией:**

| Query | Тип | Default |
|---|---|---|
| `page` | int | — |
| `per_page` | int | `20` |
| `search` | string | `null` (поиск по IP) |

```json
{
  "items": [{...}],
  "total": 150,
  "page": 0,
  "per_page": 20,
  "total_pages": 8
}
```

---

### `GET /api/blacklist/check/{ip}`
Проверить, забанен ли IP.

**Response 200 (banned):**
```json
{ "banned": true, "id": 7, "ip": "1.2.3.4", "reason": "abuse", "created_at": "..." }
```

**Response 200 (not banned):**
```json
{ "banned": false, "ip": "1.2.3.4" }
```

---

### `GET /api/blacklist/{ban_id}`
Детали бана по ID.

**Response 200:**
```json
{ "id": 7, "ip": "1.2.3.4", "reason": "abuse", "created_at": "..." }
```

**Errors:** 404.

---

### `DELETE /api/blacklist/{ban_id}`
Разбан по ID.

**Response 200:** `{ "deleted": true, "id": 7 }`. **Errors:** 404.

---

### `DELETE /api/blacklist/by-ip`
Разбан по IP (альтернатива).

**Request body:** `{ "ip": "1.2.3.4" }`

**Response 200:** `{ "deleted": true, "ip": "1.2.3.4" }`. **Errors:** 404 `"IP not in blacklist"`.

---

## 4. Relays

### `POST /api/relays`
Зарегистрировать relay-сервер в панели.

**Request body:**
```json
{
  "name": "FI-Helsinki",
  "host": "1.2.3.4",
  "agent_port": 7580,
  "agent_secret": "secret"
}
```

| Поле | Тип | Обязат. | Default |
|---|---|---|---|
| `name` | string | да | — |
| `host` | string | да | IPv4 или DNS-имя relay |
| `agent_port` | int | нет | `7580` |
| `agent_secret` | string | нет | `""` |

> ⚠ **Внимание:** в текущей версии `RelayCreate` Pydantic-модель НЕ принимает `agent_type` — relay создаётся всегда с `agent_type="full"` (default в `add_relay()`). Чтобы создать min-relay, надо обновить модель или вставлять напрямую в Supabase. На уровне БД поле есть и используется фильтрами.

**Response 200:** объект relay из БД:
```json
{
  "id": 1,
  "name": "FI-Helsinki",
  "host": "1.2.3.4",
  "agent_port": 7580,
  "agent_secret": "secret",
  "agent_type": "full",
  "is_active": true,
  "is_synced": true,
  "last_health": null,
  "last_health_at": null,
  "created_at": "..."
}
```

---

### `GET /api/relays`
Список relay'ев.

**Query:**

| Param | Default | Описание |
|---|---|---|
| `fields` | `"full"` | `"basic"` — без `last_health` (легче payload) |

**Response 200:** массив. В режиме `basic` поля: `id, name, host, agent_port, is_active, is_synced, last_health_at`.

---

### `DELETE /api/relays/{relay_id}`
Удалить relay из панели (агент на сервере остаётся работать, просто перестаёт синхронизироваться).

**Response 200:** `{ "deleted": true, "id": 1 }`.

---

### `PATCH /api/relays/{relay_id}/toggle`
Включить/выключить relay (без удаления).

**Request body:** `{ "active": false }`

**Response 200:** обновлённый объект relay.

---

### `GET /api/relays/{relay_id}/health`
Прокси на `GET /health` агента (с расширенной диагностикой).

**Response 200:** JSON от агента — см. [Relay Agent API → /health](#5-relay-agent-api).

---

### `GET /api/relays/{relay_id}/stats`
Прокси на `GET /stats` агента.

---

### `GET /api/relays/{relay_id}/traffic`
Прокси на `GET /traffic` агента.

**Query:**

| Param | Тип | Default | Описание |
|---|---|---|---|
| `summary` | bool | `false` | Только totals, без `ips` map |
| `top` | int | `null` | Только N топ-IP по трафику |

**Response 200:**
```json
{
  "ok": true,
  "relay": "FI-Helsinki",
  "month": "2026-05",
  "last_reset": "2026-05-01T00:00:00+03:00",
  "ips": {
    "1.2.3.4": {
      "tx_bytes": 100, "rx_bytes": 200, "total_bytes": 300,
      "tx_human": "100 B", "rx_human": "200 B", "total_human": "300 B",
      "clients_on_ip": 2,
      "client_ids": [1, 7],
      "updated": "2026-05-15T12:00:00+03:00"
    }
  },
  "total_tx_bytes": 100, "total_rx_bytes": 200, "total_bytes": 300,
  "total_tx": "100 B", "total_rx": "200 B", "total": "300 B",
  "ip_count": 1
}
```

`client_ids` — список clientID, привязанных к этому IP в `refcount.json` агента. У min-агента и для IP без привязки — пустой массив `[]`.

---

### `POST /api/relays/{relay_id}/sync`
Синхронизировать whitelist на конкретный relay (фоновая операция).

**Response 200:**
```json
{
  "ok": true,
  "relay": "FI-Helsinki",
  "total_clients": 150,
  "skipped_banned": 3,
  "message": "Sync started in background"
}
```

---

### `POST /api/relays/sync-all`
То же для всех full-relay параллельно.

**Response 200:**
```json
{
  "total_clients": 150,
  "skipped_banned": 3,
  "relays": {
    "FI-Helsinki": { "ok": true, "accepted": true, "received": 150, ... },
    "DE-Frankfurt": { "ok": false, "error": "timeout" }
  }
}
```

---

### `GET /api/relays/health-all`
Health-check всех relay'ев параллельно.

**Response 200:** `{ "<relay_name>": { ...health... } }`.

---

### `POST /api/relays/{relay_id}/update`
Триггер `/update` на агенте (fire-and-forget, ~100мс ответ).

**Response 200:**
```json
{
  "relay": "FI-Helsinki",
  "accepted": true,
  "message": "Update started in background",
  "check_status": "GET /health → last_update"
}
```

Если агент уже на свежей версии: `accepted: true, no_changes: true`.

Проверять результат: `GET /api/relays/{id}/health` → `last_update`.

---

### `POST /api/relays/update-all`
То же для всех relay'ев.

**Response 200:** `{ "<relay_name>": {accepted, message, ...}, ... }`.

---

### `GET /api/relays/{relay_id}/whitelist-payload`
**Внутренний endpoint** для startup-resync агента. Возвращает полный payload с расшифрованными IP клиентов и всеми активными rate_limits.

**Response 200:**
```json
{
  "clients": [
    { "ip": "1.2.3.4", "client_id": 1 }
  ],
  "rate_limits": [
    {
      "ip": "1.2.3.4",
      "mbps": 50.0,
      "expires_at": null,
      "client_id": 1
    }
  ]
}
```

---

## 5. Rate-limits

### `POST /api/rate-limits`
Установить rate-limit на IP. Применяется на все full-relay (push на агенты + сохранение в БД).

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

| Поле | Тип | Обязат. | Default | Описание |
|---|---|---|---|---|
| `ip` | string | да | — | IPv4 |
| `mbps` | float | да | — | Лимит в Mbps (`> 0`) |
| `expires_in_seconds` | int\|null | нет | `null` | TTL в секундах. `null` = бессрочно |
| `reason` | string | нет | `""` | Произвольный текст (для админки) |
| `client_id` | int\|null | нет | `null` | Связать с клиентом для аналитики |

**Response 200:**
```json
{
  "id": 5,
  "ip": "1.2.3.4",
  "mbps": 50.0,
  "reason": "fair-use",
  "expires_at": "2026-05-15T13:30:00+00:00",
  "client_id": 1,
  "created_at": "2026-05-15T12:30:00+00:00",
  "applied_to": {
    "FI-Helsinki": { "ok": true, "mark": 10 }
  }
}
```

**Errors:** `{"error": "ipv6_not_supported"}` или `{"error": "invalid_ip"}` (200), 400 `"mbps must be > 0"`.

---

### `GET /api/rate-limits`
Список всех rate-limits с пагинацией.

**Query params:**

| Param | Тип | Default | Описание |
|---|---|---|---|
| `page` | int | `0` | Номер страницы |
| `per_page` | int | `50` | Размер страницы |

**Response 200:** объект с пагинацией:
```json
{
  "items": [
    {
      "id": 5,
      "ip": "1.2.3.4",
      "mbps": 50.0,
      "reason": "fair-use",
      "expires_at": "2026-05-15T13:30:00+00:00",
      "client_id": 1,
      "created_at": "2026-05-15T12:30:00+00:00"
    }
  ],
  "total": 150,
  "page": 0,
  "per_page": 50,
  "total_pages": 3
}
```

---

### `GET /api/rate-limits/expired`
Истёкшие лимиты — для внешнего шедулера cleanup.

**Response 200:** массив (только те, у кого `expires_at < NOW`):
```json
[
  { "id": 5, "ip": "1.2.3.4", "mbps": 50.0, "expires_at": "...", "client_id": 1 }
]
```

> Внешний шедулер юзера: периодически дёргает этот endpoint и для каждой записи делает `DELETE /api/rate-limits/{ip}`.

---

### `GET /api/rate-limits/{ip}`
Получить лимит для IP.

**Response 200 (есть):**
```json
{
  "limited": true,
  "id": 5,
  "ip": "1.2.3.4",
  "mbps": 50.0,
  "expires_at": "...",
  "client_id": 1,
  "created_at": "..."
}
```

**Response 200 (нет):**
```json
{ "ip": "1.2.3.4", "limited": false }
```

---

### `DELETE /api/rate-limits/{ip}`
Снять лимит.

**Response 200:**
```json
{
  "deleted": true,
  "ip": "1.2.3.4",
  "removed_from": {
    "FI-Helsinki": { "ok": true }
  }
}
```

**Errors:** 404 если лимита нет ни в БД, ни на одном relay.

---

### `DELETE /api/rate-limits/by-ip`
То же через body (альтернатива):

**Request body:** `{ "ip": "1.2.3.4" }`

---

## 6. Stats / Dashboard / Traffic

### `GET /api/stats`
Лёгкая агрегированная статистика (один RPC `dashboard_stats`).

**Response 200:**
```json
{
  "total_clients": 150,
  "active_clients": 120,
  "blocked_clients": 5,
  "ip_bans": 3,
  "total_relays": 4,
  "active_relays": 3
}
```

---

### `GET /api/dashboard`
Главный экран админки: relays(basic) + stats.

**Response 200:**
```json
{
  "relays": [
    { "id": 1, "name": "FI-Helsinki", "host": "...", "is_active": true, ... }
  ],
  "stats": {
    "total_clients": 150,
    "active_clients": 120,
    "blocked_clients": 5,
    "ip_bans": 3,
    "total_relays": 4,
    "active_relays": 3
  }
}
```

---

### `GET /api/traffic`
Объединённый трафик со всех relay'ев. Ключ — `name` relay. Чтобы из `client_ids` получить читаемые имена — батч-эндпоинт [`POST /api/clients/labels`](#post-apiclientslabels).

**Response 200:**
```json
{
  "FI-Helsinki": {
    "ok": true,
    "relay": "FI-Helsinki",
    "month": "2026-05",
    "last_reset": "2026-05-01T00:00:00+03:00",
    "ips": {
      "1.2.3.4": {
        "tx_bytes": 100, "rx_bytes": 200, "total_bytes": 300,
        "tx_human": "100 B", "rx_human": "200 B", "total_human": "300 B",
        "clients_on_ip": 2,
        "client_ids": [1, 7],
        "updated": "2026-05-15T12:00:00+03:00"
      }
    },
    "total_tx_bytes": 100, "total_rx_bytes": 200, "total_bytes": 300,
    "total_tx": "100 B", "total_rx": "200 B", "total": "300 B",
    "ip_count": 1
  }
}
```

`client_ids` — список clientID, сидящих за этим IP (из `refcount.json` агента). Для IP без привязки — `[]`.

---

# Relay Agent API

Каждый relay-сервер слушает собственный HTTP API (по умолчанию порт 7580). Панель сама дёргает эти endpoints — но они полезны и для прямого мониторинга/диагностики.

- **Auth:** `X-Agent-Key: <secret>` (env `AGENT_SECRET`). Кроме `/health` (без авторизации).
- **Base URL:** `http://<relay-host>:7580`.
- **Два бинаря:** `warp-relay-agent` (full) и `warp-relay-agent-min` (min). Различия отмечены ниже.

## 7. Health (full + min)

### `GET /health`
**Без авторизации.** Полная диагностика агента.

**Response 200 (full):**
```json
{
  "status": "ok",
  "version": "2.1.0",
  "agent_type": "full",
  "uptime_seconds": 3600,
  "ip_forward": true,
  "ipset_count": 150,
  "online_clients": 42,
  "conntrack": "1234/65536",
  "load": 0.5,
  "memory_mb": { "used": 30, "total": 1024 },
  "cpu_percent_total": 5.2,
  "cpu_percent_per_core": [3.1, 7.3],
  "cpu_count": 2,
  "agent_process": {
    "cpu_percent": 0.5,
    "memory_mb": 25.4,
    "num_threads": 12,
    "num_fds": 42
  },
  "network_speed": {
    "rx_bps": 1500000,
    "tx_bps": 800000,
    "rx_human": "1.4 Mbps",
    "tx_human": "780 Kbps"
  },
  "disk": { "total_gb": 50, "used_gb": 12, "free_gb": 38, "percent": 24 },
  "rate_limits_count": 5,
  "traffic_month": "2026-05",
  "traffic_total": "150 GB",
  "traffic_ips": 42,
  "last_update": {
    "ok": true,
    "old_version": "2.1.0",
    "new_version": "2.2.0",
    "release_tag": "agent-v2.2.0",
    "binary_name": "warp-relay-agent",
    "started_at": "...",
    "finished_at": "..."
  },
  "last_sync": { "ok": true, "synced": 150, "clients": 150, "in_progress": false },
  "last_self_heal": { "broken": [], "actions": [] }
}
```

**Response 200 (min)** — добавляются:
```json
{
  "agent_type": "min",
  "shared_limit": 25.0,
  "shaped_clients": 8
}
```

---

## 8. Whitelist (только full)

### `POST /whitelist/update`
Добавить/обновить IP клиента.

**Request body:**
```json
{ "new_ip": "1.2.3.4", "old_ip": "5.6.7.8", "client_id": 1 }
```

| Поле | Тип | Обязат. |
|---|---|---|
| `new_ip` | string | да |
| `old_ip` | string | нет |
| `client_id` | int | нет |

**Response 200:**
```json
{ "added": "1.2.3.4", "removed": "5.6.7.8", "client_id": 1, "refcount": 1 }
```

---

### `POST /whitelist/remove`
Удалить IP (если refcount=0) или уменьшить refcount.

**Request body:** `{ "ip": "1.2.3.4" }`

**Response 200:**
```json
{ "removed": "1.2.3.4", "kept": null, "refcount": 0 }
```

---

### `POST /whitelist/sync`
Полная пересборка whitelist (fire-and-forget).

**Request body:**
```json
{ "clients": [ { "ip": "1.2.3.4", "client_id": 1 } ] }
```

**Response 200 (immediate):**
```json
{
  "accepted": true,
  "received": 150,
  "message": "Sync started in background",
  "check_status": "GET /health → last_sync"
}
```

---

### `GET /whitelist/list`
Текущий ipset.

**Response 200:**
```json
{ "ips": ["1.2.3.4", "5.6.7.8"], "count": 2, "error": null }
```

---

## 9. Rate-limits (только full)

### `POST /rate-limit`
Применить лимит на IP.

**Request body:**
```json
{ "ip": "1.2.3.4", "mbps": 50.0, "expires_at": null, "client_id": 1 }
```

**Response 200:**
```json
{
  "ok": true,
  "ip": "1.2.3.4",
  "mbps": 50.0,
  "mark": 10,
  "expires_at": null,
  "client_id": 1,
  "applied_at": "..."
}
```

### `DELETE /rate-limit/{ip}`
Снять лимит.

### `GET /rate-limit/{ip}`
Получить лимит конкретного IP.

### `GET /rate-limits`
Список всех применённых на этом агенте лимитов.

---

## 10. Traffic (full + min)

### `GET /traffic`
Месячный трафик по IP (сброс по МСК).

**Response 200:**
```json
{
  "month": "2026-05",
  "last_reset": "2026-05-01T00:00:00+03:00",
  "ips": {
    "1.2.3.4": {
      "tx_bytes": 100, "rx_bytes": 200, "total_bytes": 300,
      "tx_human": "100 B", "rx_human": "200 B", "total_human": "300 B",
      "clients_on_ip": 1,
      "client_ids": [1],
      "updated": "..."
    }
  },
  "total_tx_bytes": 100, "total_rx_bytes": 200, "total_bytes": 300,
  "total_tx": "100 B", "total_rx": "200 B", "total": "300 B",
  "ip_count": 1
}
```

`client_ids` — список clientID, привязанных к этому IP в `refcount.json`. Для min-агента и IP без привязки — `[]`.

### `GET /traffic/{ip}`
Один IP + список `client_ids` (на этом агенте).

### `POST /traffic/reset`
Принудительный сброс счётчиков. Response: `{ "ok": true, "month": "2026-05" }`.

---

## 11. Stats (full + min)

### `GET /stats`
Детальная статистика (для админ-панели).

**Response 200:**
```json
{
  "online": {
    "count": 42,
    "whitelist_total": 150,
    "conntrack_assured": 80,
    "clients": [
      { "ip": "1.2.3.4", "client_ids": [1] }
    ]
  },
  "sessions": { "assured": 80, "unreplied": 5 },
  "top_ports": { "443": 1500, "500": 300 },
  "network": { "interface": "eth0", "rx_bytes_total": 12345, "tx_bytes_total": 6789 },
  "traffic": { ...как у /traffic... }
}
```

---

## 12. Self-update (full + min)

### `POST /update`
Триггер самообновления (fire-and-forget).

**Response 200:**
```json
{
  "accepted": true,
  "message": "Update started in background",
  "check_status": "GET /health → last_update"
}
```

Внутренний flow: `git pull` → запрос к `https://api.github.com/repos/{owner}/{repo}/releases/latest` → если `tag_name` новее, скачать бинарь из release assets → atomic swap → `systemctl restart warp-relay-agent`.

Проверять результат: `GET /health` → `last_update`.

---

## 13. Refcount (только full)

### `GET /refcount`
Маппинг IP → client_ids.

**Response 200:**
```json
{ "1.2.3.4": [1, 2], "5.6.7.8": [3] }
```

---

## 14. Shaped (только min)

### `GET /shaped`
IP под shared-лимитом (автоматически от min-агента, не по запросу).

**Response 200:**
```json
{
  "items": [
    { "ip": "1.2.3.4", "mbps": 25.0, "mark": 10, "classid": 16, "lastSeen": "..." }
  ],
  "count": 1,
  "limit_mbps": 25.0,
  "scan_interval": 10,
  "idle_grace": 60
}
```

### `POST /shaped/reset`
Снять все shared-лимиты (reconcile навесит обратно на следующем тике).

---

## 15. Stub-endpoints (min)

На min-агенте все `/whitelist/*`, `/rate-limit*`, `/refcount` возвращают `200 OK`:
```json
{ "agent_type": "min", "skipped": true }
```

Панель их сама не вызывает (фильтр по `agent_type='full'` в БД), но stub защищает от ошибок ручного вызова.

---

## Cheatsheet (curl)

```bash
PANEL="http://your-panel-ip:8000"
KEY="your-api-key"

# Создать клиента
curl -X POST $PANEL/api/clients \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"label": "Иван"}'

# Ручная активация по IP
curl -X POST $PANEL/api/clients/1/activate \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4"}'

# Полные данные клиента (с rate_limit и флагами бана)
curl $PANEL/api/clients/1/full -H "X-API-Key: $KEY"

# Поиск по IP
curl "$PANEL/api/clients/search?ip=1.2.3.4" -H "X-API-Key: $KEY"

# Установить лимит 50 Mbps на час
curl -X POST $PANEL/api/rate-limits \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","mbps":50,"expires_in_seconds":3600,"client_id":1}'

# Забанить IP
curl -X POST $PANEL/api/blacklist \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","reason":"abuse"}'

# Главный экран
curl $PANEL/api/dashboard -H "X-API-Key: $KEY"

# Обновить все relay
curl -X POST $PANEL/api/relays/update-all -H "X-API-Key: $KEY"
```
