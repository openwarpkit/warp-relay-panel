# Relay diagnostics

`relay_audit.py` параллельно подключается к min/full relay по SSH и выполняет
read-only аудит агента, nftables, HTB, conntrack, iptables и системных ресурсов.

Проверяется вся цепочка ограничения:

`client IP → nft ip2mark → conntrack mark → tc HTB class → configured Mbps`

Скрипт делает два близких снимка. Кратковременное состояние нового соединения не
считается обходом лимита; ошибка помечается как `FAIL`, только если она сохраняется
в обоих снимках. Рассинхронизация служебного mark при сохранённом фактическом
лимите выводится отдельно как `WARN`.

Дополнительно проверяются:

- одинаковый набор panel rate limits на всех full relay;
- WARP-сессии min без mark и HTB-класса;
- nft/tc rate и счётчики `overlimits`/drops;
- NAT, FORWARD, whitelist/drop, CONNMARK restore и IP forwarding;
- CPU busy/steal, packet rate, interface drops/errors и conntrack capacity;
- agent health, версия, uptime, disk/memory и ошибки journal;
- conntrack client TX/RX и interface RX/TX без выгрузки полного списка клиентов.

## Подготовка

```powershell
cd tools/relay_diagnostics
python -m pip install -r requirements.txt
Copy-Item inventory.example.json inventory.local.json
Copy-Item .env.example .env
```

Заполните `inventory.local.json` своими серверами, а `.env` — паролями,
указанными через `password_env`. Оба файла исключены из git. Вместо паролей можно
указать `key_filename` в inventory. Поле `password` тоже поддерживается, но хранить
пароль прямо в JSON не рекомендуется.

По умолчанию неизвестный SSH host key отклоняется. Для первой проверки сверяйте
fingerprint сервера и добавляйте его в `known_hosts`. Флаг
`--accept-new-host-keys` разрешает подключение с предупреждением, но не сохраняет
ключ автоматически.

## Запуск

```powershell
python relay_audit.py `
  --inventory inventory.local.json `
  --env-file .env `
  --output-dir reports
```

Для Linux/macOS команда та же без PowerShell backticks.

Результат записывается в два файла:

- `relay-audit-YYYYMMDD-HHMMSS.json` — структурированные данные для автоматизации;
- `relay-audit-YYYYMMDD-HHMMSS.md` — короткий отчёт для человека или ИИ.

IP активных клиентов по умолчанию заменяются стабильными в рамках запуска
метками `ip#...`. Флаг `--include-client-ips` оставляет реальные IP в samples.
SSH-пароли и agent secrets никогда не включаются в отчёт.

Коды возврата: `0` — PASS, `1` — WARN, `2` — FAIL.

## Интерпретация трафика

На relay с одним внешним интерфейсом суммарные interface RX и TX почти равны:
пакет сначала входит на интерфейс, затем после DNAT/SNAT выходит через него же.
Это нормальная особенность forwarding и не означает двойное потребление клиента.

Full-agent считает клиентские направления из conntrack:

- TX — original direction от клиента к WARP;
- RX — reply direction от WARP к клиенту;
- потребление клиента — `TX + RX`.

Этот показатель обычно не симметричен. MIN в режиме `aggregate` считает только
интерфейсные итоги и не умеет определить потребление отдельного пользователя.

Учёт full привязан к публичному IP, а не к неизменной личности клиента. Несколько
клиентов за одним NAT получают один общий IP-total; после смены IP старый трафик не
входит в ответ endpoint, который запрашивает только текущий IP клиента.

## Ограничения измерения

Аудит подтверждает наличие и согласованность kernel rate path и наблюдает живые
conntrack/class counters. Он не создаёт тестовый трафик и не насыщает канал, поэтому
не заменяет контролируемый throughput-тест с клиентского устройства.
