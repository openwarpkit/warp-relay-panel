# WARP Relay Agent — Go (v2.1.0+)

Native Go-агент. Тот же HTTP API что был у Python-предшественника — панель работает с обоими без изменений.

**Два бинаря из одного модуля:**

| Бинарь | Назначение |
|---|---|
| `warp-relay-agent` (full) | Whitelist через ipset + per-IP rate-limit по запросам панели |
| `warp-relay-agent-min` (min) | Без whitelist — пропускает всех; автоматический симметричный лимит N Mbps (default 25) на каждый активный IP |

В панели регистрируется `agent_type:"full"|"min"`. Панель сама не шлёт whitelist/rate-limit команды на min-агента — фильтр по `agent_type='full'` в `db.get_active_relays()`.

**Преимущества:**
- Single static binary (~7 MB), без venv/pip/python3.
- Низкое потребление памяти (~15-30 MB RSS vs ~100 MB у Python).
- Endpoints: `/health`, `/whitelist/*`, `/rate-limit*`, `/traffic*`, `/refcount`, `/stats`, `/update`.

**v2.1.0 — native netlink на горячих путях:**
- `conntrack` (snapshot, accounting, ASSURED, delete, mark) — через [`ti-mo/conntrack`](https://github.com/ti-mo/conntrack) вместо `exec("conntrack -L")`.
- `ipset` (add/del/list/flush/create) — через [`vishvananda/netlink`](https://github.com/vishvananda/netlink) вместо `exec("ipset ...")`.
- `iptables`/`tc` — оставлены через shell (редкие операции).
- `ipset save > /etc/ipset.rules` — оставлен через shell (формат CLI-специфичный).

## Установка

Бинари НЕ собираются на VPS — скачиваются из GitHub Releases (release-driven flow):

```bash
sudo bash deploy/setup.sh        # full
sudo bash deploy/setup-min.sh    # min
```

Скрипт ставит пакеты, настраивает iptables/ipset/tc, скачивает свежий бинарь из `nellimonix/warp-relay-panel/releases/latest`, создаёт systemd unit. Override owner/repo: `AGENT_RELEASE_REPO=user/repo bash setup.sh`.

## Самообновление

```bash
curl -X POST -H "X-Agent-Key: $AGENT_SECRET" http://relay:7580/update
```

Агент: `git pull` (для скриптов и конфигов) → проверяет `tag_name` latest release → если новее текущей версии, скачивает свежий бинарь → atomic swap → `systemctl restart`. Сборка на сервере НЕ происходит — нагрузка ~7 MB download вместо 180s компиляции Go.

Статус последнего обновления: `GET /health → last_update`.

## Релиз-флоу (для разработчика)

Бинари собирает CI ([.github/workflows/release-agent.yml](../.github/workflows/release-agent.yml)) при создании git-тега `agent-v*`:

```bash
git tag agent-v2.2.0
git push origin agent-v2.2.0
```

Workflow собирает 4 бинаря (`warp-relay-agent`, `warp-relay-agent-min`, `*-arm64`) и аттачит к Release. После этого `setup.sh` и `/update` начнут отдавать новую версию.

## Локальная сборка (для разработки)

```bash
make build              # bin/warp-relay-agent (linux/amd64)
make build-arm64        # bin/warp-relay-agent-arm64
make build-min          # bin/warp-relay-agent-min
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
├── selfupdate/              — git pull + curl бинаря из release + systemctl restart
├── panel/                   — HTTP-клиент к панели (только full)
├── server/                  — chi router для full-агента
└── servermin/               — chi router для min-агента (stub'ами whitelist/rate-limit)
```

## Min-agent endpoints

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/health` | Расширенный health + `agent_type:"min"`, `shared_limit`, `shaped_clients` |
| GET | `/stats` | ASSURED/UNREPLIED, top dport, network speed |
| GET | `/traffic`, `/traffic/{ip}` | conntrack accounting (как у full) |
| POST | `/traffic/reset` | Сброс месячного счётчика |
| GET | `/shaped` | Текущие IP под лимитом + classid + lastSeen |
| POST | `/shaped/reset` | Снять все лимиты (reconcile навесит обратно на следующем тике) |
| POST | `/update` | self-update через download из GitHub Releases |
| (любой) | `/whitelist/*`, `/rate-limit*`, `/refcount` | **200 OK stub** `{agent_type:"min",skipped:true}` |

Панель **не должна** слать команды whitelist/rate-limit на min-агента (фильтр по `agent_type='full'`), но stub-ответы защищают от ошибок.

## Дальнейшая оптимизация

Шелл-экзеки сейчас остались только для редких операций:
- `iptables -t mangle …` при rate-limit add/remove
- `tc qdisc/class/filter add …` при rate-limit add/remove
- `iptables-restore` / `netfilter-persistent reload` в watchdog'е
- `ipset save > /etc/ipset.rules` (раз в дебаунс ~3s)

Перевод их на native netlink/nftables возможен, но дал бы единицы процентов CPU за неделю работы.
