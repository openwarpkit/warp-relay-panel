# WARP Relay Panel v1.3.0

Панель управления whitelist и rate-limit'ами для WARP Relay серверов.
Self-hosted API-панель (Docker/FastAPI + PostgreSQL), native Go-агент v2.1.0+ на relay'ях.

---

## Архитектура

```
Telegram Bot  ──HTTP──▶  Docker (FastAPI)  ──HTTP──▶  Relay Agent 1 (full)
                         PostgreSQL (соседний  ────▶  Relay Agent 2 (full)
                         контейнер на том же   ────▶  Relay Agent N (min)
                         VPS)
                              ▲
                              │
                       Клиент по ссылке
                       (определяется IPv4)
```

| Компонент | Где | Стоимость |
|-----------|-----|-----------|
| API-панель | Docker container | Ваш VPS |
| База данных | PostgreSQL (Docker, тот же VPS) | Ваш VPS |
| Relay Agent (Go) | На каждом relay-сервере (~7 MB бинарь) | VPS |
| Telegram Bot | Сервер | VPS |

**Два типа relay-агента:**

- **`full`** — whitelist через `ipset` + индивидуальные rate-limit'ы по запросам панели. Используется для подписчиков.
- **`min`** — без whitelist, пропускает всех. Накладывает общий лимит N Mbps (default 25) на каждый активный клиентский IP. Используется для бесплатных/общих relay'ев.

---

## Быстрый старт

### 1. Панель + PostgreSQL (docker-compose) — 5 минут

Панель и БД поднимаются одним `docker-compose.yml`: образ панели тянется из
ghcr, Postgres стартует рядом и при первом запуске сам применяет
[db/schema.sql](db/schema.sql). Подробный гайд (запуск с нуля и миграция данных
из Supabase) — в [DEPLOY.md](DEPLOY.md).

```bash
git clone https://github.com/openwarpkit/warp-relay-panel.git /opt/warp-relay-panel
cd /opt/warp-relay-panel
cp .env.example .env        # заполнить значения (см. таблицу ниже)
docker compose up -d
```

Переменные окружения в `.env`:

| Переменная | Значение |
|------------|----------|
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | имя БД / пользователь / пароль Postgres |
| `DATABASE_URL` | строка подключения (в compose собирается из `POSTGRES_*`, host = `db`) |
| `ENCRYPTION_KEY` | Сгенерировать: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `API_KEY` | Любой секретный ключ для бота |
| `AGENT_SECRET` | Общий секрет для relay-агентов |

> ⚠ При миграции с Supabase оставьте **тот же** `ENCRYPTION_KEY`, иначе ранее
> сохранённые IP не расшифруются.

### 2. Relay-сервер — 1 команда

Бинари приходят из GitHub Releases — на VPS не собирается ничего:

```bash
ssh root@RELAY_IP

git clone https://github.com/openwarpkit/warp-relay-panel.git /opt/warp-relay-panel
sudo bash /opt/warp-relay-panel/relay-agent/deploy/setup.sh        # full
# или
sudo bash /opt/warp-relay-panel/relay-agent/deploy/setup-min.sh    # min
```

Скрипт спросит `Agent secret` (тот же `AGENT_SECRET`, что в конфигурации панели) и порт (default 7580). Скачает свежий бинарь из [releases/latest](https://github.com/openwarpkit/warp-relay-panel/releases/latest), настроит iptables/ipset/tc, заведёт systemd unit, включит автовосстановление правил при перезагрузке.

Override owner/repo для форка: `AGENT_RELEASE_REPO=user/repo bash setup.sh`.

### 3. Добавить relay в панель

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

### 4. Создать клиента

```bash
curl -X POST ${PANEL}/api/clients \
  -H "X-API-Key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d '{"label": "Иван"}'

# Ответ: {"id": 1, "token": "a1b2c3d4e5f67890", ...}
# Ссылка: http://your-panel-ip:8000/activate/a1b2c3d4e5f67890
```

### 5. Синхронизация

```bash
curl -X POST ${PANEL}/api/relays/sync-all -H "X-API-Key: ${KEY}"
```

---

## Обновление relay-серверов

**Release-driven flow:** агент НЕ собирается на VPS. CI собирает бинари при создании git-тега, агент скачивает свежий бинарь из GitHub Releases.

```bash
# Обновить все relay (fire-and-forget):
curl -X POST ${PANEL}/api/relays/update-all -H "X-API-Key: ${KEY}"

# Обновить один:
curl -X POST ${PANEL}/api/relays/{id}/update -H "X-API-Key: ${KEY}"
```

Что происходит на агенте при `/update`:
1. `git pull` (для скриптов/конфигов в `/opt/warp-relay-panel`).
2. GitHub API → узнать `tag_name` latest release.
3. Если новее — скачать `warp-relay-agent` (или `-min`) из release assets.
4. Atomic swap бинаря + `systemctl restart`.

Время: ~10-30 секунд (вместо ~3 минут компиляции). Нагрузка на VPS: ~7 MB download.

Проверить результат — через `/health` каждого relay:
```bash
curl -X GET ${PANEL}/api/relays/{id}/health -H "X-API-Key: ${KEY}"
# → "last_update": {"ok": true, "release_tag": "agent-v2.2.0", "finished_at": "..."}
```

### Создание нового релиза агента

```bash
git tag agent-v2.2.0
git push origin agent-v2.2.0
```

Workflow [.github/workflows/release-agent.yml](.github/workflows/release-agent.yml) соберёт `warp-relay-agent`, `warp-relay-agent-min`, `*-arm64` и аттачит к Release.

### Автовосстановление при перезагрузке

При каждом запуске агент (через `ExecStartPre`) проверяет и восстанавливает ipset + iptables правила из сохранённых конфигов (`rules_recipe.json`).

---

## Безопасность

### ENCRYPTION_KEY — критически важно

`ENCRYPTION_KEY` используется для шифрования IP-адресов клиентов в базе данных (Fernet AES-128-CBC).

> **⚠️ Если сменить `ENCRYPTION_KEY` — все ранее зашифрованные IP станут нечитаемыми.** Клиенты будут отображаться с ошибкой `decrypt_error`, активации продолжат работать (новые IP с новым ключом), но история будет потеряна.

**Правила:**
- Сгенерировать один раз: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- Сохранить в надёжном месте (password manager).
- Никогда не менять после начала работы с клиентами.
- Не коммитить в git.

### Relay-агент

Агент слушает на порту 7580 по HTTP. Защита:

```bash
# Если есть фиксированный IP панели:
ufw allow from PANEL_IP to any port 7580
ufw deny 7580
```

Для повышения безопасности запросы защищены через `AGENT_SECRET` (`X-Agent-Key` header).

### Шифрование в базе

Все IP-адреса хранятся зашифрованными (Fernet). Для поиска используется SHA-256 хэш. IP-бан лист тоже зашифрован. Даже при утечке базы — IP не раскрываются.

---

## API панели

Все `/api/*` эндпоинты требуют заголовок `X-API-Key`.

### Клиенты

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/clients` | Создать `{"label":"..."}` |
| `GET` | `/api/clients` | Список всех (`?include_blocked=false`) |
| `GET` | `/api/clients/search?ip=1.2.3.4` | Поиск по current/previous IP + история активаций |
| `GET` | `/api/clients/{id}` | Детали клиента |
| `GET` | `/api/clients/{id}/full` | Клиент + флаги бана + текущий rate-limit (1 RPC) |
| `POST` | `/api/clients/{id}/activate` | Ручная активация по IP `{"ip":"1.2.3.4"}` (для бота) |
| `GET` | `/api/clients/{id}/logs` | История активаций (`?limit=50`) |
| `DELETE` | `/api/clients/{id}/logs` | Очистить историю активаций |
| `GET` | `/api/clients/{id}/traffic` | Трафик клиента со всех relay |
| `PATCH` | `/api/clients/{id}/block` | Блокировать `{"blocked": true}` |
| `DELETE` | `/api/clients/{id}` | Удалить (+ убрать IP с relay) |

> **Общий IP:** при блокировке/удалении клиента IP удаляется с relay только если никто другой на этом IP не сидит (refcount).

### Relay-серверы

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/relays` | Добавить `{name, host, agent_port, agent_secret, agent_type:"full"\|"min"}` |
| `GET` | `/api/relays` | Список (`?fields=basic` — без last_health) |
| `DELETE` | `/api/relays/{id}` | Удалить |
| `PATCH` | `/api/relays/{id}/toggle` | Вкл/выкл `{"active": false}` |
| `GET` | `/api/relays/{id}/health` | Здоровье + `last_update` |
| `GET` | `/api/relays/{id}/stats` | Статистика (клиенты, трафик, порты) |
| `GET` | `/api/relays/{id}/traffic` | Трафик по IP (`?summary=true`, `?top=10`) |
| `POST` | `/api/relays/{id}/sync` | Синхронизировать whitelist (только full) |
| `POST` | `/api/relays/{id}/update` | Обновить агент (fire-and-forget) |
| `GET` | `/api/relays/{id}/whitelist-payload` | Полный payload для startup-resync (внутреннее) |
| `POST` | `/api/relays/sync-all` | Синхронизировать все full-relay |
| `POST` | `/api/relays/update-all` | Обновить все relay |
| `GET` | `/api/relays/health-all` | Проверить все relay |

### IP-блэклист (хард-бан)

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/blacklist` | Забанить `{"ip":"1.2.3.4", "reason":"..."}` |
| `GET` | `/api/blacklist` | Список (`?page=0&per_page=20&search=1.2.3.4`) |
| `GET` | `/api/blacklist/check/{ip}` | Проверить IP |
| `GET` | `/api/blacklist/{id}` | Детали бана |
| `DELETE` | `/api/blacklist/{id}` | Разбанить по ID |
| `DELETE` | `/api/blacklist/by-ip` | Разбанить `{"ip":"1.2.3.4"}` |

> **IP-бан** блокирует активацию для ЛЮБОГО клиента с этим IP. Клиенты не блокируются — могут активироваться с другого IP.

### Rate-limits (per-IP, в Mbps)

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/rate-limits` | Установить `{"ip","mbps","expires_in_seconds"?,"reason"?,"client_id"?}` |
| `GET` | `/api/rate-limits` | Список всех |
| `GET` | `/api/rate-limits/expired` | Истёкшие (для внешнего шедулера cleanup) |
| `GET` | `/api/rate-limits/{ip}` | Получить лимит для IP |
| `DELETE` | `/api/rate-limits/{ip}` | Снять лимит |
| `DELETE` | `/api/rate-limits/by-ip` | Снять `{"ip":"..."}` (альтернатива) |

> Rate-limits применяются только на full-relay (через CONNMARK + HTB). На min-relay — общий shared limit.

### Трафик / Статистика / Активация

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/api/traffic` | Трафик со всех relay (по IP) |
| `GET` | `/api/stats` | Лёгкая статистика через RPC `dashboard_stats` |
| `GET` | `/api/dashboard` | Главный экран: relays(basic) + stats |
| `GET` | `/activate/{token}` | Активация по ссылке (публичный, HTML) |
| `GET` | `/health` | Healthcheck |

---

## Relay Agent API

Порт 7580. Все эндпоинты (кроме `/health`) требуют `X-Agent-Key`.

### Full-агент

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/whitelist/update` | `{"new_ip":"...", "old_ip":"...", "client_id": 1}` |
| `POST` | `/whitelist/remove` | `{"ip":"..."}` |
| `POST` | `/whitelist/sync` | `{"clients":[{"ip","client_id"}]}` (фоновая пересборка) |
| `GET` | `/whitelist/list` | Текущий ipset |
| `POST` | `/rate-limit` | `{"ip","mbps","expires_at"?,"client_id"?}` |
| `DELETE` | `/rate-limit/{ip}` | Снять лимит |
| `GET` | `/rate-limit/{ip}` | Получить лимит |
| `GET` | `/rate-limits` | Список всех лимитов |
| `GET` | `/traffic` | Трафик по IP за месяц (сброс по МСК) |
| `GET` | `/traffic/{ip}` | Конкретный IP + `clients_on_ip` |
| `POST` | `/traffic/reset` | Принудительный сброс |
| `GET` | `/stats` | Клиенты, порты, сессии, трафик |
| `GET` | `/refcount` | Маппинг IP → client_ids |
| `GET` | `/health` | Системный статус + `last_update` (без авторизации) |
| `POST` | `/update` | Самообновление через GitHub Releases (fire-and-forget) |

### Min-агент

Те же `/health`, `/stats`, `/traffic*`, `/update` + специфичные:

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/shaped` | IP под shared-лимитом + classid + lastSeen |
| `POST` | `/shaped/reset` | Снять все shared-лимиты (reconcile навесит обратно) |

Эндпоинты `/whitelist/*` и `/rate-limit*` на min-агенте возвращают `200 OK stub` (`{agent_type:"min", skipped:true}`) — панель их сама не дёргает (фильтр по `agent_type='full'`), но stub защищает от ошибок.

## Тестирование (Fuzzing, Benchmarks, API)

В проекте настроено несколько уровней автоматизированного тестирования для обеспечения производительности и безопасности.

### Go-агент (Unit, Fuzzing, Benchmarks)

Тесты агента лежат в директории `relay-agent`.

```bash
cd relay-agent

# Запуск обычных unit-тестов
make test

# Запуск Fuzz-тестов (проверка устойчивости к повреждению файлов состояния на диске)
# Будут запущены FuzzRefcountLoad, FuzzRatelimitLoad и FuzzTrafficLoad
# Можно менять FUZZTIME (по умолчанию 10s)
make test-fuzz FUZZTIME=5s

# Запуск Benchmarks (проверка производительности и отсутствия аллокаций в hot paths)
make test-bench
```

### Панель FastAPI (Интеграционные тесты)

"Зародыш" интеграционных тестов для API-панели использует `TestClient` и mock-заглушки базы данных (без необходимости поднимать реальный PostgreSQL).

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt pytest respx pytest-asyncio
pytest api/tests/
```

---

## Интеграция с Telegram-ботом

<details>
<summary><b>Пример для aiogram 3</b></summary>

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

## Структура проекта

```
warp-relay-panel/
├── api/                              # Backend панели (Python FastAPI)
│   ├── index.py                      # FastAPI (роуты, активация, blacklist, rate-limits)
│   ├── database.py                   # PostgreSQL (async psycopg3 + пул)
│   ├── relay_client.py               # HTTP-клиент к relay-агентам
│   ├── crypto.py                     # Шифрование IP (Fernet)
│   └── cache.py                      # In-memory TTL кэш
├── relay-agent/                      # Go-агент (ставится на каждый relay)
│   ├── cmd/agent/                    # full-агент
│   ├── cmd/agent-min/                # min-агент
│   ├── internal/                     # модули (server, selfupdate, ratelimit, ...)
│   ├── deploy/
│   │   ├── setup.sh                  # установка full
│   │   ├── setup-min.sh              # установка min
│   │   ├── ensure_rules.sh           # восстановление iptables/ipset (full)
│   │   ├── ensure_rules_min.sh       # восстановление для min
│   │   ├── warp-relay-agent.service
│   │   └── warp-relay-agent-min.service
│   ├── go.mod / go.sum
│   ├── Makefile
│   └── README.md
├── .github/workflows/
│   ├── release-agent.yml             # build & release бинарей по тегу agent-v*
│   └── docker-build.yml
├── db/schema.sql                     # SQL: таблицы + функции (источник истины)
├── docker-compose.yml                # панель + postgres
├── DEPLOY.md                         # запуск с нуля + миграция данных
├── requirements.txt                  # Python зависимости
└── .env.example                      # Переменные окружения
```

---

## Changelog

### v1.3.0 (актуальная)
- **Релиз-флоу через GitHub Actions:** бинари агента собираются CI и аттачатся к release при создании тега `agent-v*`. На VPS теперь ничего не компилируется.
- **Self-update download-driven:** агент при `/update` скачивает свежий бинарь из GitHub Releases (~10-30 сек) вместо `make build` (~180 сек).
- Удалён старый Python relay-agent (полностью на Go v2.1.0+).
- Удалены deprecated поля БД: `clients.note`, `clients.activations_today`, `clients.activations_reset_date`, `activation_log.user_agent`.
- Удалён дневной лимит активаций (`MAX_ACTIVATIONS_PER_DAY`).
- Все миграции схлопнуты в единый `db/schema.sql` (источник истины), включая SQL-функции.

### v2.1.0 — Go-агент
- Полная переписка relay-agent с Python на Go (single static binary ~7 MB).
- Native netlink на горячих путях (`conntrack`, `ipset`) — резкое падение CPU.
- NAT rules management + per-IP rate-limit через CONNMARK + HTB.
- Поддержка двух типов агентов: `full` (whitelist + per-IP rate-limit) и `min` (без whitelist, общий лимит на каждый активный IP).
- prebuilt-бинари (теперь живут в GitHub Releases, не в репо).

### v1.2.2
- Фоновая синхронизация whitelist через `/whitelist/sync`.
- Статус последней синхронизации в `/health` → `last_sync`.
- Пагинация выборок из БД.
- Исправлено удаление осиротевших IP из ipset.

### v1.2.1
- Обновление relay через API (fire-and-forget).
- Статус последнего обновления в `/health` → `last_update`.
- Timezone МСК на всех relay (трафик сбрасывается по московскому времени).

### v1.2.0
- IP-блэклист (хард-бан по IP).
- Защита общих IP (refcount на панели и агенте).
- Мониторинг трафика по IP (conntrack accounting).
- Фильтрация ботов (Telegram preview и др.).
- Автовосстановление iptables/ipset при перезагрузке.

### v1.0.0
- Первый релиз.
