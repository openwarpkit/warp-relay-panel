# Промт для следующего аудита

```text
Проведи read-only аудит всех WARP relay из
tools/relay_diagnostics/inventory.local.json с помощью
tools/relay_diagnostics/relay_audit.py. Установленные в inventory типы min/full и
лимиты считаются ожидаемой конфигурацией. Не меняй состояние серверов, не запускай
нагрузочный тест и не показывай пароли, agent secrets или полные списки клиентских
IP.

Запусти скрипт с локальным tools/relay_diagnostics/.env, изучи JSON и Markdown
отчёты, а затем дай вывод на русском:

1. Есть ли на min устойчивые WARP-сессии с mark=0, без nft mapping, без HTB class
   или с фактическим rate выше configured limit.
2. Одинаковы ли panel rate limits на всех full relay и проходит ли каждый лимит
   цепочку agent → nft → conntrack → tc с правильным Mbps.
3. Есть ли активный ограниченный пользователь, который фактически идёт через
   default/unlimited class. Отдели bypass от безвредного stale mark/class.
4. Оцени service health, CPU busy/steal, packet rate, drops/errors, память, диск и
   заполнение conntrack. Назови проблемные relay.
5. Объясни client TX/RX и interface RX/TX. Для full оцени conntrack accounting,
   для min явно укажи, доступен ли per-user accounting.
6. Составь короткий приоритетный список действий. Любые исправления сначала только
   предложи, не применяй без отдельного разрешения.

Сошлись на конкретных полях и check codes из отчёта. Если SSH к серверу недоступен,
не делай вывод о его исправности.
```
