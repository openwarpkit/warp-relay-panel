# WARP Relay Panel v1.2.0

Панель управления whitelist для WARP Relay серверов.  
Бесплатный хостинг на **Vercel + Supabase**.

---

## Архитектура

```
Telegram Bot  ──HTTP──▶  Vercel (FastAPI)  ──HTTP──▶  Relay Agent 1
                         Supabase (PostgreSQL)  ────▶  Relay Agent 2
                              ▲                 ────▶  Relay Agent N
                              │
                       Клиент по ссылке
                       (определяется IPv4)
```

| Компонент | Где | Стоимость |
|-----------|-----|-----------|
| API-панель | Vercel serverless | Бесплатно |
| База данных | Supabase PostgreSQL | Бесплатно (500 MB) |
| Relay Agent | На каждом relay-сервере | VPS |
| Telegram Bot | Сервер | VPS |

---

## Быстрый старт

### 1. Панель (Vercel + Supabase) — 5 минут

**Supabase:**
1. Создать проект на [supabase.com](https://supabase.com)
2. **SQL Editor** → вставить `supabase_schema.sql` → Run
3. Скопировать **Project URL** и **service_role key**

**Vercel — деплой одной кнопкой:**

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/openwarpkit/warp-relay-panel&repository-name=warp-relay-panel)

После деплоя → **Settings → Environment Variables** → задать:

| Переменная | Значение |
|------------|----------|
| `SUPABASE_URL` | `https://xxx.supabase.co` |
| `SUPABASE_KEY` | `eyJ...service-role-key...` |
| `ENCRYPTION_KEY` | Сгенерировать: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `API_KEY` | Любой секретный ключ для бота |
| `AGENT_SECRET` | Общий секрет для relay-агентов |
| `MAX_ACTIVATIONS_PER_DAY` | `10` (0 = без лимита) |

→ **Redeploy** чтобы подхватить переменные.

### 2. Relay-сервер — 1 команда

```bash
ssh root@RELAY_IP

# Установка
curl -fsSL https://raw.githubusercontent.com/openwarpkit/warp-relay-panel/main/relay-agent/setup_relay.sh | bash

# Или через git (рекомендуется — проще обновлять):
git clone https://github.com/openwarpkit/warp-relay-panel.git /opt/warp-relay-panel
bash /opt/warp-relay-panel/relay-agent/setup_relay.sh
```

Скрипт спросит `Agent secret` (тот же что `AGENT_SECRET` на Vercel) и порт (по умолчанию 7580).

### 3. Добавить relay в панель

```bash
PANEL="https://your-project.vercel.app"
KEY="your-api-key"

curl -X POST ${PANEL}/api/relays \
  -H "X-API-Key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d '{"name": "FI-Helsinki", "host": "1.2.3.4", "agent_port": 7580}'
```

### 4. Создать клиента

```bash
curl -X POST ${PANEL}/api/clients \
  -H "X-API-Key: ${KEY}" \
  -H "Content-Type: application/json" \
  -d '{"label": "Иван", "note": "подписчик"}'

# Ответ: {"id": 1, "token": "a1b2c3d4e5f67890", ...}
# Ссылка: https://your-project.vercel.app/activate/a1b2c3d4e5f67890
```

### 5. Синхронизация

```bash
# Синхронизировать whitelist + refcount на все relay
curl -X POST ${PANEL}/api/relays/sync-all -H "X-API-Key: ${KEY}"
```

---

## Обновление relay-серверов

### Все сразу (через API)
curl -X POST ${PANEL}/api/relays/update-all -H "X-API-Key: ${KEY}"

### Один relay
curl -X POST ${PANEL}/api/relays/{id}/update -H "X-API-Key: ${KEY}"

### Автовосстановление при перезагрузке

Агент автоматически при запуске:
- Проверяет наличие ipset и iptables правил
- Если правила пропали — восстанавливает из сохранённых конфигов
- Делает `ipset restore` и `netfilter-persistent reload`

Дополнительно настроены systemd-сервисы `ipset-restore.service` и `netfilter-persistent` для восстановления до старта агента.

---

<details>
<summary><b>Ручная установка relay (без git)</b></summary>

```bash
# Скопировать папку relay-agent на сервер
scp -r relay-agent root@RELAY_IP:/tmp/

# Запустить
ssh root@RELAY_IP "bash /tmp/relay-agent/setup_relay.sh"

# Проверить
ssh root@RELAY_IP 'curl -s http://localhost:7580/health | python3 -m json.tool'
```

В этом режиме `update.sh` не будет работать — обновлять нужно вручную через scp.

</details>

<details>
<summary><b>Ручной деплой Vercel (без кнопки)</b></summary>

```bash
cd warp-relay-panel
npm i -g vercel
vercel
# Задать переменные в Dashboard → Settings → Environment Variables
vercel --prod
```

</details>

---

## API

Все `/api/*` эндпоинты требуют заголовок `X-API-Key`.

### Клиенты

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/clients` | Создать `{"label":"...", "note":"..."}` |
| `GET` | `/api/clients` | Список всех (`?include_blocked=false`) |
| `GET` | `/api/clients/{id}` | Детали клиента |
| `GET` | `/api/clients/{id}/logs` | История активаций |
| `GET` | `/api/clients/{id}/traffic` | Трафик клиента со всех relay |
| `PATCH` | `/api/clients/{id}/block` | Блокировать `{"blocked": true}` |
| `DELETE` | `/api/clients/{id}` | Удалить (+ убрать IP с relay) |

> **Общий IP:** при блокировке/удалении клиента его IP удаляется с relay только если никто другой на этом IP не сидит (защита от обрыва доступа соседей по сети).

### Relay-серверы

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/relays` | Добавить relay |
| `GET` | `/api/relays` | Список |
| `DELETE` | `/api/relays/{id}` | Удалить |
| `PATCH` | `/api/relays/{id}/toggle` | Вкл/выкл `{"active": false}` |
| `GET` | `/api/relays/{id}/health` | Здоровье relay |
| `GET` | `/api/relays/{id}/stats` | Статистика (клиенты, трафик, порты) |
| `GET` | `/api/relays/{id}/traffic` | Потребление трафика по IP |
| `POST` | `/api/relays/{id}/sync` | Синхронизировать whitelist |
| `POST` | `/api/relays/sync-all` | Синхронизировать все relay |
| `GET` | `/api/relays/health-all` | Проверить все relay |

### IP-блэклист (хард-бан)

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/api/blacklist` | Забанить `{"ip":"1.2.3.4", "reason":"торренты"}` |
| `GET` | `/api/blacklist` | Список всех банов |
| `GET` | `/api/blacklist/check/{ip}` | Проверить IP |
| `DELETE` | `/api/blacklist/{id}` | Разбанить по ID |
| `DELETE` | `/api/blacklist/by-ip` | Разбанить `{"ip":"1.2.3.4"}` |

> **IP-бан** блокирует активацию для ЛЮБОГО клиента с этим IP. IP автоматически удаляется с relay. Клиенты не блокируются — они могут активироваться с другого IP.

### Трафик

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/api/traffic` | Трафик со всех relay (по IP) |

### Активация (публичный)

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/activate/{token}` | Активация по ссылке (HTML) |

> Автоматическая фильтрация ботов (Telegram preview, Googlebot и др.) — бот получает OG-мету, активация не срабатывает.

### Прочее

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/api/stats` | Общая статистика |
| `GET` | `/health` | Healthcheck |

---

## Relay Agent API

Работает на каждом relay-сервере (порт 7580).  
Все эндпоинты (кроме `/health`) требуют заголовок `X-Agent-Key`.

### Whitelist

| Метод | Путь | Описание |
|-------|------|----------|
| `POST` | `/whitelist/update` | `{"new_ip":"...", "old_ip":"...", "client_id": 1}` |
| `POST` | `/whitelist/remove` | `{"ip":"..."}` |
| `POST` | `/whitelist/sync` | `{"clients":[{"ip":"...", "client_id": 1}]}` |
| `GET` | `/whitelist/list` | Текущий ipset |

> **Refcount-защита:** агент ведёт маппинг IP → client_ids. Если два клиента на одном IP — при уходе одного IP не удаляется.

### Трафик (по IP, для администратора)

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/traffic` | Все IP с потреблением за месяц |
| `GET` | `/traffic/{ip}` | Конкретный IP + `clients_on_ip` |
| `POST` | `/traffic/reset` | Принудительный сброс |

> Трафик считается через conntrack byte counters каждые 30 сек. Автосброс 1-го числа месяца.

### Мониторинг

| Метод | Путь | Описание |
|-------|------|----------|
| `GET` | `/health` | Система, ipset, conntrack, трафик (без авторизации) |
| `GET` | `/stats` | Клиенты, порты, сессии, трафик |
| `GET` | `/refcount` | Маппинг IP → client_ids (для отладки) |

---

## Безопасность

### Relay-агент

Агент слушает на порту 7580 по HTTP. Защита:

```bash
# Если есть фиксированный IP панели:
ufw allow from PANEL_IP to any port 7580
ufw deny 7580
```

Если фиксированного IP нет (Vercel serverless) — защита через `AGENT_SECRET`.

### Шифрование

Все IP-адреса клиентов в базе хранятся зашифрованными (Fernet AES-128-CBC). Для поиска используется SHA-256 хэш. Даже при утечке базы — IP не раскрываются.

---

## Интеграция с Telegram-ботом

<details>
<summary><b>Пример для aiogram 3</b></summary>

```python
import aiohttp

PANEL_URL = "https://your-project.vercel.app"
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
            f"{PANEL_URL}/api/clients/{client_id}",
            headers=HEADERS,
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

async def get_client_traffic(client_id: int) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{PANEL_URL}/api/clients/{client_id}/traffic",
            headers=HEADERS,
        ) as resp:
            return await resp.json()
```

</details>

---

## Структура проекта

```
warp-relay-panel/
├── api/                        # Vercel serverless
│   ├── index.py                # FastAPI (роуты, активация, блэклист)
│   ├── database.py             # Supabase операции
│   ├── relay_client.py         # HTTP-клиент для relay-агентов
│   └── crypto.py               # Шифрование IP (Fernet)
├── relay-agent/                # Ставится на каждый relay
│   ├── agent.py                # FastAPI агент (ipset, трафик, refcount)
│   ├── setup_relay.sh          # Полная установка
│   ├── update.sh               # Обновление агента
│   ├── ensure_rules.sh         # Восстановление iptables/ipset
│   ├── requirements.txt
│   └── .env.example
├── supabase_schema.sql         # SQL для создания таблиц
├── ip_blacklist_migration.sql  # Миграция: таблица IP-банов
├── vercel.json                 # Конфигурация Vercel
├── requirements.txt            # Python зависимости (Vercel)
└── .env.example                # Переменные окружения
```

---

## Changelog

### v1.2.0
- IP-блэклист (хард-бан по IP)
- Защита общих IP (refcount на панели и агенте)
- Мониторинг трафика по IP (conntrack accounting)
- Фильтрация ботов (Telegram preview и др.)
- Автовосстановление iptables/ipset при перезагрузке
- Скрипт массового обновления relay-серверов

### v1.0.1
- Исправлен `ipset destroy` → `ipset flush` (sync падал при привязке к iptables)

### v1.0.0
- Первый релиз