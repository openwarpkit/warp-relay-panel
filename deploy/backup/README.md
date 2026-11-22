# Резервное копирование WARP Relay Panel

| Назначение | Расписание по Москве | Хранение |
| --- | --- | --- |
| Hetzner Storage Box, Compose-сервис `backup` | Каждый час, с 00:00 до 23:00 | Сегодня и 29 предыдущих календарных дней |
| Telegram, `warp-relay-panel-backup.timer` | Ежедневно в 00:30 | Существующая политика Telegram и локального хранилища |

Hetzner хранит полные дампы PostgreSQL в архивах 7z с AES-256 и зашифрованными заголовками. Путь относительно корня SFTP-сессии имеет вид `warp-relay-panel/2026-11-22/08-00.7z`. Архив содержит дамп в формате `pg_restore` и манифест с идентификатором установки, временем снимка и SHA-256 дампа. Пароль от 7z и ключ шифрования данных панели храните отдельно. Копия Telegram по-прежнему включает настроенный набор файлов восстановления панели, а почасовая копия содержит базу данных.

Контейнер работает без root и Docker socket. Он подключается к PostgreSQL по сети Compose под отдельной ролью чтения. После перезагрузки Docker запускает контейнер автоматически. При старте обрабатывается текущий час и отправляется максимум один локальный зашифрованный архив, если предыдущая отправка прервалась. Ошибка повторяется с интервалом до пяти минут. Дамп и распакованные файлы хранятся в ограниченном tmpfs. Зашифрованный архив остаётся в локальной очереди до проверки отправки.

SFTP-сервис публикует архив после проверки SHA-256 загруженного файла. Ротация проходит после успешной отправки и сверки метки владельца. Она удаляет только файлы установленного формата из каталогов с датами старше порога. Старые каталоги с посторонними файлами остаются в хранилище.

## Подготовка

1. Скопируйте `docker-compose.backup.yml` рядом с рабочим Compose-файлом. Сохраните текущее имя проекта Compose и действующие файлы переопределений. Укажите в `.env` путь к существующему закрытому ключу в `BACKUP_SSH_KEY`. Если владелец ключа использует UID или GID, отличный от `1000`, задайте `BACKUP_UID` или `BACKUP_GID`. Для конфигурации и состояния используйте каталоги `/etc/warp-relay-hetzner-backup` и `/var/lib/warp-relay-hetzner-backup` с режимом `0700` и владельцем ключа. Создайте в каталоге состояния `backup.lock` с режимом `0600` от имени этого владельца. Telegram использует тот же файл блокировки.
2. От имени администратора PostgreSQL создайте роль `warp_backup` с `LOGIN` и задайте пароль интерактивно через `\password warp_backup` в `psql`. Выдайте ей `CONNECT` на базу панели, `USAGE` на схему `public`, `SELECT` на таблицы и последовательности этой схемы. Для новых объектов задайте такие же права через `ALTER DEFAULT PRIVILEGES FOR ROLE` от имени владельца объектов.
3. Поместите в каталог конфигурации `config.json` на основе `storage.example.json` с данными выделенного субаккаунта, `pgpass` в формате `db:5432:warp:warp_backup:<пароль>` и `archive_password` с отдельной случайной фразой длиной от 24 символов. При нестандартных именах базы или роли согласуйте `pgpass` со значениями `POSTGRES_DB` и `BACKUP_POSTGRES_USER`. Файлы с секретами должны иметь режим `0600`. Закрепите ключ сервера Storage Box для записи `[хост]:23` в `known_hosts` и сверьте его отпечаток. [Документация Hetzner](https://docs.hetzner.com/storage/storage-box/general/#ssh-host-keys)
4. Соберите контейнер и проверьте доступ. Команда `init` создаёт каталог проекта и метку установки. Для существующего каталога она проверяет ту же метку или требует пустой каталог.

```bash
dc() { docker compose -f docker-compose.yml -f recovery-volume.yml -f docker-compose.backup.yml --profile backup "$@"; }
dc config -q
dc build backup
dc run --rm --no-deps backup check
dc run --rm --no-deps backup init
dc run --rm --no-deps backup once
dc run --rm --no-deps backup list
dc run --rm --no-deps backup restore-test '2026-11-22/08-00.7z'
```

5. Подставьте существующий архив в `restore-test`. После успешного восстановления запустите `dc up -d --no-deps backup`. Затем установите обновлённые `panel_backup.py`, `warp-relay-panel-backup.service` и `warp-relay-panel-backup.timer` по их текущим путям. Выполните `systemctl daemon-reload` и `systemctl enable warp-relay-panel-backup.timer`, затем `systemctl restart warp-relay-panel-backup.timer`. Сохраните существующую конфигурацию Telegram, включая подпись, тему и пароль архива.

## Управление

```bash
dc run --rm --no-deps backup once
dc run --rm --no-deps backup status
dc run --rm --no-deps backup list
dc run --rm --no-deps backup verify '2026-11-22/08-00.7z'
dc logs --tail 100 backup
dc stop backup
dc start backup
journalctl -u warp-relay-panel-backup.service -n 50
systemctl list-timers warp-relay-panel-backup.timer
```

`once` пропускает повторную отправку за уже подтверждённый час. `status` возвращает путь, SHA-256 и время подтверждения последней копии. Код завершения будет ненулевым, если сохранённому снимку больше двух часов или снимка ещё нет. `verify` скачивает указанный архив и проверяет CRC архива, хеш дампа и манифест.

## Переименование архивов

Соберите новый образ, остановите почасовой контейнер и приостановите ручные записи в каталог проекта. Команда миграции использует тот же локальный каталог состояния и блокировку, что и обычное резервное копирование.

```bash
dc build backup
dc stop backup
dc run --rm --no-deps backup migrate-names
dc run --rm --no-deps backup migrate-names --apply
dc run --rm --no-deps backup list
dc run --rm --no-deps backup verify '2026-11-22/08-00.7z'
dc run --rm --no-deps backup verify '2026-11-22/08:00.7z'
dc run --rm --no-deps backup restore-test '2026-11-22/08-00.7z'
dc up -d --no-deps backup
```

Для проверки подставьте существующий архив из списка. При конфликте команда выводит оба пути и завершает работу. После прерывания повторите `migrate-names --apply` с тем же каталогом состояния. Исходные SHA-256 хранятся в `archive-name-migration.json`. Миграция сравнивает их с результатом по новым путям и обновляет имя в `last-success.json`, сохраняя время и SHA-256 последней копии.

## Пробное восстановление

1. Получите точный путь копии через `dc run --rm --no-deps backup list`.
2. Выполните `dc run --rm --no-deps backup restore-test 'YYYY-MM-DD/HH-MM.7z'`. Команды `verify` и `restore-test` также принимают пути вида `YYYY-MM-DD/HH:MM.7z`. Восстановление создаёт отдельный PostgreSQL-кластер в tmpfs с доступом через локальный Unix-сокет и проверяет, что таблица `clients` читается. Контейнер и тестовая база удаляются по завершении.
3. Чтобы сохранить восстановленную базу для анализа, скачайте выбранный архив по SFTP в защищённый каталог на тестовой машине. Распакуйте его через `7z x ./backup.7z` с интерактивным вводом пароля. Сверьте результат `sha256sum database.dump` с `dump_sha256` в манифесте. Подключившись к отдельному тестовому кластеру PostgreSQL 17, создайте пустую базу через `createdb -h /путь/к/тестовому/сокету warp_restore_test` и запустите `pg_restore -h /путь/к/тестовому/сокету --exit-on-error --no-owner --no-acl -d warp_restore_test database.dump`.
