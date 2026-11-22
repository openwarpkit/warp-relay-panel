import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta
import fcntl
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from zoneinfo import ZoneInfo

from backup_archive import create_archive, file_hash, inspect_archive
import storage_box


MSK = ZoneInfo('Europe/Moscow')
PENDING_PATTERN = re.compile(r'[0-9]{8}T(?:[01][0-9]|2[0-3])\.7z')
STATE = Path('/state')
CONFIG = Path('/run/backup/config.json')
KNOWN_HOSTS = Path('/run/backup/known_hosts')
PRIVATE_KEY = Path('/run/backup-ssh-key')
PASSWORD_FILE = Path('/run/backup/archive_password')
DUMP = 'database.dump'
MANIFEST = 'RESTORE_MANIFEST.json'


class BackupError(RuntimeError):
    pass


def log(message):
    print(f'{datetime.now(MSK).isoformat(timespec="seconds")} {message}', flush=True)


def command(*args, timeout=60):
    subprocess.run(args, check=True, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_config():
    config = json.loads(CONFIG.read_text())
    for key in ('server_id', 'host', 'user'):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', config[key]):
            raise BackupError('Invalid backup configuration field ' + key)
    namespace = config.setdefault('directory', storage_box.PROJECT)
    if not re.fullmatch(storage_box.PROJECT + r'(?:-[a-z0-9-]{1,64})?', namespace):
        raise BackupError('Invalid Storage Box project directory')
    config.setdefault('port', 23)
    config.setdefault('retention_days', 30)
    config.setdefault('max_archive_bytes', 256 * 1024 * 1024)
    if not 1 <= config['port'] <= 65535 or min(config['retention_days'], config['max_archive_bytes']) < 1:
        raise BackupError('Invalid backup configuration limits')
    return config


def archive_password():
    password = PASSWORD_FILE.read_text().rstrip('\r\n')
    if len(password) < 24:
        raise BackupError('Archive password must contain at least 24 characters')
    return password


def check_database():
    command('pg_isready', '-q', '-t', '10')
    command('psql', '-X', '-w', '-v', 'ON_ERROR_STOP=1', '-c', 'SELECT 1')


@contextmanager
def lock():
    with (STATE / 'backup.lock').open('a+b') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise BackupError('Another backup or restore is running') from None
        yield


def replace_state_file(staging, target):
    staging.replace(target)
    descriptor = os.open(STATE, os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_state_json(name, result):
    staging = STATE / ('.' + name + '.tmp')
    with staging.open('w') as target:
        json.dump(result, target)
        target.flush()
        os.fsync(target.fileno())
    replace_state_file(staging, STATE / name)


def read_state_json(name):
    path = STATE / name
    return json.loads(path.read_text()) if path.is_file() else {}


def save_status(archive, size, digest):
    write_state_json('last-success.json', {
        'archive': archive, 'size': size, 'sha256': digest, 'verified_at': datetime.now(MSK).isoformat(),
    })


def last_success():
    return read_state_json('last-success.json')


def pending_archive(config, slot):
    check_database()
    with tempfile.TemporaryDirectory(prefix='dump-') as temporary:
        work = Path(temporary)
        payload = work / 'payload'
        payload.mkdir()
        dump = payload / DUMP
        command('pg_dump', '-w', '--format=custom', '--compress=none', '--no-owner',
                '--no-acl', '--lock-wait-timeout=15s', '-f', str(dump), timeout=600)
        command('pg_restore', '--list', str(dump))
        manifest = {
            'server_id': config['server_id'],
            'database': os.environ['PGDATABASE'],
            'slot': storage_box.archive_path(slot),
            'created_at': datetime.now(MSK).isoformat(),
            'dump_sha256': file_hash(dump),
        }
        (payload / MANIFEST).write_text(json.dumps(manifest, indent=2))
        archive = work / 'archive.7z'
        create_archive(archive, payload, archive_password())
        size = archive.stat().st_size
        log(f'Dump bytes={dump.stat().st_size} archive bytes={size}; encrypted round trip verified')
        if not 0 < size <= config['max_archive_bytes']:
            raise BackupError('Encrypted archive exceeds the configured spool limit')
        staging = STATE / '.archive.tmp'
        with archive.open('rb') as source, staging.open('wb') as target:
            shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
        result = STATE / slot.strftime('%Y%m%dT%H.7z')
        replace_state_file(staging, result)
        return result


def deliver(config, slot, archive):
    started = time.monotonic()
    relative = storage_box.archive_path(slot)
    try:
        with storage_box.connect(config, PRIVATE_KEY, KNOWN_HOSTS) as sftp:
            root = storage_box.project_root(sftp, config['directory'])
            storage_box.verify_owner(sftp, root, config['server_id'])
            size, digest = storage_box.publish(sftp, root, slot, archive)
        result = 'Published and verified'
    except storage_box.ExistingArchive:
        relative, size, digest = check_archive(config, relative, restore=False)
        result = 'Recovered verified existing archive'
    save_status(relative, size, digest)
    archive.unlink()
    log(f'{result} {relative} bytes={size} seconds={time.monotonic() - started:.1f}')


def run_backup(config):
    slot = datetime.now(MSK).replace(minute=0, second=0, microsecond=0)
    relative = storage_box.archive_path(slot)
    log(f'Starting slot {relative}')
    (STATE / '.archive.tmp').unlink(missing_ok=True)
    pending = [path for path in STATE.iterdir() if PENDING_PATTERN.fullmatch(path.name)]
    if len(pending) > 1:
        raise BackupError('More than one undelivered archive in the local spool')
    if pending:
        pending_slot = datetime.strptime(pending[0].name, '%Y%m%dT%H.7z').replace(tzinfo=MSK)
        deliver(config, pending_slot, pending[0])
    previous = last_success().get('archive')
    if not previous or storage_box.parse_archive(previous) != slot.replace(tzinfo=None):
        deliver(config, slot, pending_archive(config, slot))
    cutoff = slot.date() - timedelta(days=config['retention_days'] - 1)
    with storage_box.connect(config, PRIVATE_KEY, KNOWN_HOSTS) as sftp:
        root = storage_box.project_root(sftp, config['directory'])
        removed = storage_box.prune(sftp, root, config['server_id'], cutoff)
    log(f'Finished {relative} oldest_date={cutoff} removed={removed}')


def restore_test(dump, directory):
    pgdata = directory / 'pgdata'
    socket = directory / 'socket'
    socket.mkdir()
    overrides = dict(os.environ, PGHOST=str(socket), PGPORT='5432', PGUSER='restore_admin',
                     PGDATABASE='postgres', PGPASSFILE='/dev/null')
    subprocess.run(['initdb', '-D', str(pgdata), '-A', 'trust', '--no-locale', '-U', 'restore_admin'],
                   check=True, timeout=90, capture_output=True)
    try:
        command('pg_ctl', '-D', str(pgdata), '-w', '-t', '45', '-l', str(directory / 'postgres.log'),
                '-o', f"-c listen_addresses='' -k {socket}", 'start')
        subprocess.run(['createdb', '-w', 'restore_test'], env=overrides, check=True, timeout=30,
                       capture_output=True)
        subprocess.run(['pg_restore', '-w', '--exit-on-error', '--no-owner', '--no-acl',
                        '-d', 'restore_test', str(dump)], env=overrides, check=True, timeout=600,
                       capture_output=True)
        subprocess.run(['psql', '-X', '-w', '-d', 'restore_test', '-v', 'ON_ERROR_STOP=1',
                        '-c', 'SELECT count(*) FROM public.clients'], env=overrides,
                       check=True, timeout=60, capture_output=True)
    finally:
        subprocess.run(['pg_ctl', '-D', str(pgdata), '-w', '-t', '30', '-m', 'immediate', 'stop'],
                       timeout=45, capture_output=True)


def check_archive(config, archive, restore):
    slot = storage_box.parse_archive(archive)
    with tempfile.TemporaryDirectory(prefix='verify-') as temporary:
        work = Path(temporary)
        local = work / 'archive.7z'
        with storage_box.connect(config, PRIVATE_KEY, KNOWN_HOSTS) as sftp, local.open('wb') as target:
            root = storage_box.project_root(sftp, config['directory'])
            storage_box.verify_owner(sftp, root, config['server_id'])
            archive = storage_box.resolve_archive(sftp, root, archive)
            size, digest = storage_box.read_archive(
                sftp, posixpath.join(root, archive), config['max_archive_bytes'], target,
            )
        output = work / 'payload'
        hashes = inspect_archive(local, archive_password(), output)
        if set(hashes) != {DUMP, MANIFEST}:
            raise BackupError('Unexpected archive contents')
        manifest = json.loads((output / MANIFEST).read_text())
        if (manifest['server_id'], storage_box.parse_archive(manifest['slot']),
            manifest['database'], manifest['dump_sha256']) != (
            config['server_id'], slot, os.environ['PGDATABASE'], hashes[DUMP],
        ):
            raise BackupError('Archive manifest mismatch')
        command('pg_restore', '--list', str(output / DUMP))
        if restore:
            restore_test(output / DUMP, work)
            log('Isolated PostgreSQL restore verified')
        log(f'Verified {archive} bytes={size} sha256={digest}')
        return archive, size, digest


def migrate_status(sftp, root, limit, records):
    status = last_success()
    if not status:
        return
    old = status['archive']
    new = storage_box.archive_path(storage_box.parse_archive(old))
    if new == old:
        return
    verified = records.get(old)
    if verified is None:
        target = posixpath.join(root, new)
        storage_box.directory(sftp, posixpath.dirname(target))
        verified = storage_box.read_archive(sftp, target, limit)
    if tuple(verified) != (status['size'], status['sha256']):
        raise BackupError(f'Last successful archive checksum mismatch: {new}')
    status['archive'] = new
    write_state_json('last-success.json', status)
    log(f'Last successful archive path updated to {new}')


def migrate_names(config, apply):
    name = 'archive-name-migration.json'
    with storage_box.connect(config, PRIVATE_KEY, KNOWN_HOSTS) as sftp:
        root = storage_box.project_root(sftp, config['directory'])
        storage_box.verify_owner(sftp, root, config['server_id'])
        scope = [config['server_id'], config['user'], config['host'], config['port'], root]
        journal = read_state_json(name)
        resuming = bool(journal and not journal['complete'])
        if resuming and journal['scope'] != scope:
            raise BackupError('Archive migration journal belongs to a different Storage Box')
        records = journal['archives'] if resuming else {}
        moves = storage_box.migration_plan(sftp, root, records)
        if resuming and {old for old, _, _ in moves} != records.keys():
            extra = sorted(old for old, _, _ in moves if old not in records)
            raise BackupError('Archives appeared after migration started:\n' + '\n'.join(extra))
        if not apply:
            for old, new, rename in moves:
                log(f'{"Rename" if rename else "Verify"} {old} -> {new}')
            log(f'Preflight checked {len(moves)} archive paths')
            return

        limit = config['max_archive_bytes']
        for old, new, rename in moves:
            path = old if rename else new
            content = list(storage_box.read_archive(sftp, posixpath.join(root, path), limit))
            if old in records and records[old] != content:
                raise BackupError(f'Archive migration checksum mismatch: {path}')
            records[old] = content
        if storage_box.migration_plan(sftp, root, records) != moves:
            raise BackupError('Archive paths changed during migration preflight')
        if moves and not resuming:
            write_state_json(name, {'scope': scope, 'archives': records, 'complete': False})
        for old, new, rename in moves:
            expected = tuple(records[old])
            target = posixpath.join(root, new)
            if rename:
                try:
                    sftp.rename(posixpath.join(root, old), target)
                except OSError as error:
                    if storage_box.lstat(sftp, target) is not None:
                        raise BackupError(f'Archive rename was interrupted or conflicted: {old} -> {new}') from None
                    raise BackupError(f'Archive rename failed: {old} -> {new}') from error
                if storage_box.read_archive(sftp, target, limit) != expected:
                    raise BackupError(f'Renamed archive checksum mismatch: {old} -> {new}')
            log(f'Verified {old} -> {new} bytes={expected[0]} sha256={expected[1]}')
        migrate_status(sftp, root, limit, records)
        if moves:
            write_state_json(name, {'scope': scope, 'archives': records, 'complete': True})
        log(f'Migration complete, verified archives={len(moves)}')


def stop_worker(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def run_once():
    with tempfile.TemporaryDirectory(prefix='worker-') as scratch:
        with subprocess.Popen(
            [sys.executable, __file__, '_run'], start_new_session=True,
            env=dict(os.environ, TMPDIR=scratch),
        ) as process:
            try:
                return process.wait(timeout=2400)
            finally:
                stop_worker(process)


def schedule():
    while True:
        now = datetime.now(MSK)
        next_hour = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        try:
            status = run_once()
        except subprocess.TimeoutExpired:
            log('Hourly backup timed out')
            status = 1
        seconds = (next_hour - datetime.now(MSK)).total_seconds()
        time.sleep(max(0, seconds if status == 0 else min(300, seconds)))


def exit_on_signal(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='action', required=True)
    for action in ('schedule', 'once', '_run', 'status', 'check', 'init', 'list'):
        subparsers.add_parser(action)
    for action in ('verify', 'restore-test'):
        subparsers.add_parser(action).add_argument('archive')
    subparsers.add_parser('migrate-names').add_argument('--apply', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGTERM, exit_on_signal)
    signal.signal(signal.SIGINT, exit_on_signal)
    if args.action == 'schedule':
        schedule()
    if args.action == 'once':
        return run_once()
    if args.action == 'status':
        result = last_success()
        print(json.dumps(result))
        if not result:
            return 1
        slot = storage_box.parse_archive(result['archive']).replace(tzinfo=MSK)
        return int(datetime.now(MSK) - slot > timedelta(hours=2))
    config = read_config()
    if args.action in ('_run', 'verify', 'restore-test', 'migrate-names'):
        with lock():
            if args.action == '_run':
                run_backup(config)
            elif args.action == 'migrate-names':
                migrate_names(config, args.apply)
            else:
                check_archive(config, args.archive, args.action == 'restore-test')
        return 0
    if args.action == 'check':
        check_database()
    with storage_box.connect(config, PRIVATE_KEY, KNOWN_HOSTS) as sftp:
        root = storage_box.project_root(sftp, config['directory'])
        if args.action == 'check':
            log(f'PostgreSQL and SFTP available; project path={root}')
        elif args.action == 'init':
            with lock():
                storage_box.initialize(sftp, root, config['server_id'])
                log(f'Initialized project path={root}')
        else:
            storage_box.verify_owner(sftp, root, config['server_id'])
            for path, size in storage_box.list_archives(sftp, root):
                print(f'{path}\t{size}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (BackupError, storage_box.StorageError) as error:
        log(str(error))
        sys.exit(1)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        log(f'{error.cmd[0]} failed: {type(error).__name__}')
        sys.exit(1)
    except Exception as error:
        log(f'Backup operation failed: {type(error).__name__}')
        sys.exit(1)
