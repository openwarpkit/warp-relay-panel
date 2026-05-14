# WARP Relay Agent — Go (v2.1.0)

Go-rewrite Python-агента из [relay-agent/](../relay-agent/). Тот же HTTP API 1:1 — панель работает с обоими без изменений.

**Два бинаря из одного модуля:**

| Бинарь | Назначение |
|---|---|
| `warp-relay-agent` (full) | Whitelist через ipset + per-IP rate-limit по запросам панели |
| `warp-relay-agent-min` (min) | Без whitelist — пропускает всех; автоматический симметричный лимит N Mbps (default 25) на каждый активный IP. Заменяет старый bash-прототип с `conntrack -L | awk` каждые 10s. |

Сборка: `make build` (full) и `make build-min` (min). В панели регистрируется `agent_type:"full"|"min"` (требует миграции `supabase/migrations/003_agent_type.sql`). Панель сама не шлёт whitelist/rate-limit команды на min-агента — фильтр по `agent_type='full'` в `db.get_active_relays()`.

**Преимущества:**
- Single static binary (~7 MB), без venv/pip/python3.
- Низкое потребление памяти (~15-30 MB RSS vs ~100 MB у Python).
- Точно такие же endpoints: `/health`, `/whitelist/*`, `/rate-limit*`, `/traffic*`, `/refcount`, `/stats`, `/update`.

**v2.1.0 — native netlink на горячих путях:**
- `conntrack` (snapshot, accounting, ASSURED, delete, mark) — через [`ti-mo/conntrack`](https://github.com/ti-mo/conntrack) вместо `exec("conntrack -L")`. Это и был источник CPU-спайков: убираем fork+конвертацию-в-текст+regex-парсинг.
- `ipset` (add/del/list/flush/create) — через [`vishvananda/netlink`](https://github.com/vishvananda/netlink) вместо `exec("ipset ...")`.
- `iptables`/`tc` — оставлены через shell (редкие операции в watchdog/rate-limit, переход на nftables/native-tc дал бы микропроцентный выигрыш за большой риск).
- `ipset save > /etc/ipset.rules` — оставлен через shell (формат файла CLI-специфичный).

## Установка с нуля

```bash
sudo bash deploy/setup.sh
```

Скрипт: ставит пакеты, Go-тулчейн (если нет), настраивает iptables/ipset/tc, собирает бинарь, заводит systemd unit.

## Миграция с Python-агента

На relay'е, где сейчас крутится Python-агент:

```bash
# 1. Остановить старый
sudo systemctl stop warp-relay-agent

# 2. Бэкапнуть state (refcount/traffic совместимы — JSON-формат тот же)
sudo cp /opt/warp-relay-agent/refcount.json /opt/warp-relay-agent/refcount.json.bak

# 3. Запустить новый setup (он перезапишет systemd unit и бинарь)
cd /opt/warp-relay-panel
sudo git pull
sudo bash relay-agent-go/deploy/setup.sh

# 4. Проверить
curl http://localhost:7580/health
journalctl -u warp-relay-agent -f
```

State-файлы (`refcount.json`, `traffic.json`, `rate_limits.json`) совместимы по формату с Python-агентом — миграция бесшовная.

## Сборка вручную

```bash
make build              # bin/warp-relay-agent (linux/amd64)
make build-arm64        # bin/warp-relay-agent-arm64
make fmt vet            # форматирование и проверки
```

## Структура

```
cmd/
├── agent/main.go            — full: debounced ipset persist, startup-resync
└── agent-min/main.go        — min: sharedlimit reconcile loop
internal/
├── config/                  — env loader (общий, +новые env для min)
├── shell/                   — обёртка вокруг exec, ValidIPv4, FormatBytes
├── conntrackgo/             — netlink-обёртка ti-mo/conntrack
├── ipsetgo/                 — netlink-обёртка vishvananda/netlink (ipset)
├── refcount/                — IP→clients map с JSON persist (только full)
├── traffic/                 — conntrack accounting + monthly aggregation
├── ratelimit/               — CONNMARK + HTB (используется и full и min)
├── sharedlimit/             — reconcile loop для min: conntrack scan + rl.Set/Remove
├── metrics/                 — gopsutil sampler
├── watchdog/                — self-heal loop (SkipIpset для min)
├── selfupdate/              — git pull + make build + systemd restart
├── panel/                   — HTTP-клиент к панели (только full)
├── server/                  — chi router для full-агента
└── servermin/               — chi router для min-агента (со stub'ами whitelist/rate-limit)
```

## Min-agent: установка

```bash
# На чистом сервере (без full-агента):
sudo bash deploy/setup-min.sh
# Спросит: AGENT_SECRET, AGENT_PORT (default 7580), SHARED_LIMIT_MBPS (default 25)

# Зарегистрировать в панели:
curl -X POST https://panel.example/api/relays \
  -H "X-API-Key: ..." \
  -d '{"name":"min-1","host":"...","agent_port":7580,"agent_secret":"...","agent_type":"min"}'
```

### Min-agent endpoints

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/health` | Расширенный health + `agent_type:"min"`, `shared_limit`, `shaped_clients` |
| GET | `/stats` | ASSURED/UNREPLIED, top dport, network speed |
| GET | `/traffic`, `/traffic/{ip}` | conntrack accounting (как у full) |
| POST | `/traffic/reset` | Сброс месячного счётчика |
| GET | `/shaped` | Текущие IP под лимитом + classid + lastSeen |
| POST | `/shaped/reset` | Снять все лимиты (reconcile навесит обратно на следующем тике) |
| POST | `/update` | self-update через git pull + make build-min |
| (любой) | `/whitelist/*`, `/rate-limit*`, `/refcount` | **200 OK stub** `{agent_type:"min",skipped:true}` |

Панель **не должна** слать команды whitelist/rate-limit на min-агента (фильтр по `agent_type='full'`), но stub-ответы защищают от ошибок.

## Дальнейшая оптимизация

Шелл-экзеки сейчас остались только для редких операций:
- `iptables -t mangle …` при rate-limit add/remove (раз в час)
- `tc qdisc/class/filter add …` при rate-limit add/remove
- `iptables-restore` / `netfilter-persistent reload` в watchdog'е (раз в месяц)
- `ipset save > /etc/ipset.rules` (раз в дебаунс ~3s)

Перевод их на native netlink/nftables возможен, но дал бы единицы процентов CPU за неделю работы — оставлено в shell сознательно.
