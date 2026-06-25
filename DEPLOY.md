# Деплой панели (Docker Compose + PostgreSQL)

Панель и БД работают рядом на одном VPS: образ панели тянется из
`ghcr.io/openwarpkit/warp-relay-panel:latest`, PostgreSQL — соседний контейнер.
При первом старте Postgres сам применяет [db/schema.sql](db/schema.sql)
(таблицы + SQL-функции). База наружу **не публикуется** — доступна только из
docker-сети по адресу `db:5432`.

---

## 1. Запуск с нуля

```bash
git clone https://github.com/openwarpkit/warp-relay-panel.git /opt/warp-relay-panel
cd /opt/warp-relay-panel
cp .env.example .env
nano .env            # заполнить POSTGRES_PASSWORD, ENCRYPTION_KEY, API_KEY, AGENT_SECRET
docker compose up -d
docker compose ps
curl -fsS http://127.0.0.1:8000/health   # {"status":"ok","version":"...","db":"ok"}
```

`.env` (обязательное):

| Переменная | Назначение |
|---|---|
| `POSTGRES_DB` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | параметры контейнера `db` |
| `DATABASE_URL` | строка подключения панели; в compose собирается из `POSTGRES_*` (host = `db`). Менять не нужно, если не запускаете панель вне compose |
| `ENCRYPTION_KEY` | Fernet-ключ шифрования IP. **Менять нельзя** — иначе старые IP не расшифруются |
| `API_KEY` | ключ бота (`X-API-Key`) |
| `AGENT_SECRET` | общий секрет relay-агентов (`X-Agent-Key`) |

> Контейнер `db` намеренно **без** метки watchtower — Postgres остаётся на
> закреплённой версии и не автообновляется.

---

## 2. Миграция данных из Supabase

Строку подключения возьмите в Supabase: **Project Settings → Database →
Connection string (Direct)**. Шифрование переносится «как есть» — главное
оставить **тот же** `ENCRYPTION_KEY`.

> ⚠ **Порядок важен.** Если у вас включён watchtower, сначала остановите его —
> иначе он подтянет новый образ панели раньше, чем будет готова БД, и панель
> уйдёт в рестарт-цикл.

```bash
# 0) остановить watchtower на время миграции
docker stop watchtower || true

# 1) выгрузить данные нужных таблиц из Supabase
pg_dump "postgresql://postgres:<PW>@db.<REF>.supabase.co:5432/postgres" \
  --data-only --no-owner --no-privileges \
  -t clients -t relays -t activation_log -t ip_blacklist -t rate_limits \
  > supabase_data.sql

# 2) поднять только БД (init применит db/schema.sql)
docker compose up -d db
docker compose exec db pg_isready -U warp -d warp

# 3) залить данные
docker compose cp supabase_data.sql db:/tmp/data.sql
docker compose exec db psql -U warp -d warp -f /tmp/data.sql

# 4) поправить sequence'ы под BIGSERIAL (иначе новые INSERT упрутся в PK)
docker compose exec db psql -U warp -d warp -c "
  SELECT setval(pg_get_serial_sequence('clients','id'),        COALESCE((SELECT MAX(id) FROM clients),1));
  SELECT setval(pg_get_serial_sequence('relays','id'),         COALESCE((SELECT MAX(id) FROM relays),1));
  SELECT setval(pg_get_serial_sequence('activation_log','id'), COALESCE((SELECT MAX(id) FROM activation_log),1));
  SELECT setval(pg_get_serial_sequence('ip_blacklist','id'),   COALESCE((SELECT MAX(id) FROM ip_blacklist),1));
  SELECT setval(pg_get_serial_sequence('rate_limits','id'),    COALESCE((SELECT MAX(id) FROM rate_limits),1));"

# 5) запустить панель и проверить
docker compose up -d app
curl -fsS http://127.0.0.1:8000/health

# 6) вернуть watchtower
docker start watchtower || true
```

Проверьте после миграции: `GET /api/clients`, `GET /api/relays`, активацию по
ссылке. Supabase-проект оставьте на несколько дней как резервную копию.

---

## 3. Бэкап / восстановление

```bash
# бэкап
docker compose exec db pg_dump -U warp -d warp --no-owner > backup_$(date +%F).sql

# восстановление в чистую БД
docker compose exec -T db psql -U warp -d warp < backup_YYYY-MM-DD.sql
```

Том данных — docker volume `pgdata` (переживает пересоздание контейнеров).

---

## 4. Обновление панели

Watchtower обновляет только контейнер `app` (по метке
`com.centurylinklabs.watchtower.enable=true`). Вручную:

```bash
docker compose pull app && docker compose up -d app
```

Схема меняется редко; `db/schema.sql` идемпотентен (`CREATE ... IF NOT EXISTS`,
`CREATE OR REPLACE FUNCTION`). Чтобы применить изменения схемы к уже работающей
БД, выполните файл вручную:

```bash
docker compose cp db/schema.sql db:/tmp/schema.sql
docker compose exec db psql -U warp -d warp -f /tmp/schema.sql
```

---

## 5. Откат на Supabase

Образ панели для отката должен быть прежней версии (до миграции). Верните старый
`.env` с `SUPABASE_URL`/`SUPABASE_KEY` и прежний тег образа — данные в Supabase
не удалялись.
