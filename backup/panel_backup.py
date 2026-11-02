import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


ARCHIVE_PATTERN = re.compile(r'^warp-db-\d{8}-\d{6}\.7z$')
MSK = timezone(timedelta(hours=3))
SNAPSHOT_SOURCE = '''import json,os,sys,psycopg
from psycopg import sql
connection=psycopg.connect(os.environ['DATABASE_URL'],autocommit=True)
connection.execute('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY')
try:
 snapshot=connection.execute('SELECT pg_export_snapshot()').fetchone()[0]
 tables=connection.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").fetchall()
 counts={name:connection.execute(sql.SQL('SELECT count(*) FROM public.{}').format(sql.Identifier(name))).fetchone()[0] for (name,) in tables}
 print(json.dumps({'snapshot':snapshot,'counts':counts}),flush=True)
 sys.stdin.buffer.read(1)
finally:
 connection.execute('ROLLBACK')
 connection.close()
'''


class BackupError(RuntimeError):
    pass


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def run(command, *, data=None, timeout=600):
    result = subprocess.run(command, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        raise BackupError('Subprocess failed: ' + Path(command[0]).name)
    return result.stdout


def secure_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise BackupError('Directory must not be a symlink')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path.resolve()


@contextmanager
def backup_lock(path):
    path = Path(path)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_uid != os.geteuid():
            raise BackupError('Lock owner mismatch')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True
    finally:
        os.close(fd)


def archive_worker(config, operation, archive, work, password, source=None, output=None):
    name = 'warp-relay-backup-archive-' + uuid.uuid4().hex[:12]
    command = [
        'docker', 'run', '--rm', '-i', '--name', name, '--network', 'none', '--cpus', '1',
        '--memory', '1g', '--mount', 'type=bind,src=' + str(work) + ',dst=/work',
        config['helper_image'],
    ]
    payload = {'operation': operation, 'archive': '/work/' + str(archive.relative_to(work)), 'password': password}
    if source:
        payload['source'] = '/work/' + str(source.relative_to(work))
    if output:
        payload['output'] = '/work/' + str(output.relative_to(work))
    try:
        result = run(command, data=json.dumps(payload).encode(), timeout=900)
        return json.loads(result)
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def export_database(config, output):
    command = ['docker', 'exec', '-i', config['panel_container'], 'python', '-c', SNAPSHOT_SOURCE]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        line = process.stdout.readline()
        if not line:
            raise BackupError('Snapshot export failed')
        metadata = json.loads(line)
        snapshot = metadata['snapshot']
        if not re.fullmatch(r'[0-9A-Fa-f-]+', snapshot):
            raise BackupError('Invalid snapshot identifier')
        dump_command = [
            'docker', 'exec', config['database_container'], 'pg_dump',
            '-U', config['database_user'], '-d', config['database_name'],
            '--no-owner', '--no-acl', '--snapshot', snapshot,
        ]
        with output.open('wb') as target:
            result = subprocess.run(dump_command, stdout=target, stderr=subprocess.PIPE, timeout=600)
        if result.returncode or output.stat().st_size == 0:
            raise BackupError('Database dump failed')
        return metadata
    finally:
        if process.stdin:
            try:
                process.stdin.write(b'1')
                process.stdin.flush()
            except BrokenPipeError:
                pass
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def telegram_json(token, method, fields):
    request = urllib.request.Request(
        'https://api.telegram.org/bot' + token + '/' + method,
        data=urllib.parse.urlencode(fields).encode(),
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        raise BackupError('Telegram HTTP ' + str(error.code)) from None
    except Exception:
        raise BackupError('Telegram transport failed') from None
    if not data.get('ok'):
        raise BackupError('Telegram rejected ' + method)
    return data['result']


def send_document(config, archive):
    boundary = 'backup' + uuid.uuid4().hex
    body = bytearray()
    fields = {'chat_id': str(config['chat_id']), 'message_thread_id': str(config['message_thread_id']), 'disable_notification': 'true'}
    for key, value in fields.items():
        body.extend(('--' + boundary + '\r\nContent-Disposition: form-data; name="' + key + '"\r\n\r\n' + value + '\r\n').encode())
    body.extend(('--' + boundary + '\r\nContent-Disposition: form-data; name="document"; filename="' + archive.name + '"\r\nContent-Type: application/x-7z-compressed\r\n\r\n').encode())
    body.extend(archive.read_bytes())
    body.extend(('\r\n--' + boundary + '--\r\n').encode())
    request = urllib.request.Request(
        'https://api.telegram.org/bot' + config['telegram_token'] + '/sendDocument',
        data=body, headers={'Content-Type': 'multipart/form-data; boundary=' + boundary},
    )
    try:
        with urllib.request.urlopen(request, timeout=240) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        raise BackupError('Telegram upload HTTP ' + str(error.code)) from None
    except Exception:
        raise BackupError('Telegram upload failed') from None
    if not result.get('ok'):
        raise BackupError('Telegram rejected document upload')
    message = result['result']
    document = message.get('document', {})
    if message.get('chat', {}).get('id') != config['chat_id'] or message.get('message_thread_id') != config['message_thread_id']:
        raise BackupError('Telegram destination mismatch')
    if document.get('file_name') != archive.name or document.get('file_size') != archive.stat().st_size:
        raise BackupError('Telegram document metadata mismatch')
    return {'message_id': message['message_id'], 'file_id': document['file_id'], 'file_unique_id': document.get('file_unique_id'), 'file_size': document['file_size']}


def download_document(config, file_id, target):
    info = telegram_json(config['telegram_token'], 'getFile', {'file_id': file_id})
    path = info.get('file_path', '')
    if not path or '..' in Path(path).parts or path.startswith('/'):
        raise BackupError('Invalid Telegram file path')
    url = 'https://api.telegram.org/file/bot' + config['telegram_token'] + '/' + path
    try:
        with urllib.request.urlopen(url, timeout=180) as response, target.open('wb') as output:
            shutil.copyfileobj(response, output)
    except Exception:
        raise BackupError('Telegram download failed') from None


def split_archive(archive, part_bytes):
    if part_bytes < 1 or part_bytes > 19 * 1024 * 1024:
        raise BackupError('Invalid Telegram part size')
    if archive.stat().st_size <= part_bytes:
        return [archive]
    parts = []
    with archive.open('rb') as source:
        number = 1
        while True:
            chunk = source.read(part_bytes)
            if not chunk:
                break
            part = archive.with_name(archive.name + '.' + str(number).zfill(3))
            with part.open('xb') as output:
                output.write(chunk)
            part.chmod(0o600)
            parts.append(part)
            number += 1
    return parts


def join_parts(parts, output):
    with output.open('wb') as target:
        for part in parts:
            with part.open('rb') as source:
                shutil.copyfileobj(source, target)


def restore_test(config, directory, sql_file, counts):
    name = 'warp-relay-backup-verify-' + uuid.uuid4().hex[:12]
    env = directory / 'restore-postgres.env'
    env.write_text('POSTGRES_USER=warp\nPOSTGRES_DB=warp\nPOSTGRES_PASSWORD=' + secrets.token_urlsafe(36) + '\n')
    env.chmod(0o600)
    run(['docker', 'run', '-d', '--name', name, '--network', 'none', '--cpus', '1', '--memory', '512m', '--env-file', str(env), config['postgres_image']], timeout=120)
    try:
        for attempt in range(60):
            result = subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'warp', '-d', 'warp'], capture_output=True)
            if result.returncode == 0:
                break
            time.sleep(1)
        else:
            raise BackupError('Restore-test database not ready')
        with sql_file.open('rb') as source:
            result = subprocess.run(['docker', 'exec', '-i', name, 'psql', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'warp', '-d', 'warp'], stdin=source, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=600)
        if result.returncode:
            raise BackupError('Independent database restore failed')
        actual = {}
        for table in counts:
            quoted = '"' + table.replace('"', '""') + '"'
            result = run(['docker', 'exec', name, 'psql', '-At', '-U', 'warp', '-d', 'warp', '-c', 'SELECT count(*) FROM public.' + quoted])
            actual[table] = int(result.strip())
        if actual != counts:
            raise BackupError('Restored table counts differ from exported snapshot')
        return {'verified': True, 'counts': actual}
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def prune_delivered(directory, keep, installation_id):
    delivered = []
    for archive in directory.iterdir():
        if not ARCHIVE_PATTERN.fullmatch(archive.name) or not archive.is_file() or archive.is_symlink():
            continue
        receipt = archive.with_suffix('.receipt.json')
        if receipt.is_symlink() or not receipt.is_file():
            continue
        try:
            data = json.loads(receipt.read_text())
            if data.get('installation_id') == installation_id and data.get('delivery_verified') is True and data.get('sha256') == file_hash(archive):
                parts = []
                for part in data.get('parts', []):
                    name = part.get('file_name', '')
                    if name == archive.name:
                        continue
                    if not re.fullmatch(re.escape(archive.name) + r'\.\d{3,}', name):
                        raise ValueError('Invalid retained part name')
                    target = directory / name
                    if target.is_symlink() or not target.is_file() or file_hash(target) != part.get('sha256'):
                        raise ValueError('Retained part checksum mismatch')
                    parts.append(target)
                delivered.append((archive, receipt, parts))
        except (ValueError, OSError):
            continue
    delivered.sort(key=lambda pair: pair[0].name, reverse=True)
    for archive, receipt, parts in delivered[max(0, keep):]:
        for part in parts:
            part.unlink()
        archive.unlink()
        receipt.unlink()
    return len(delivered[max(0, keep):])


def perform(config, verify_restore):
    config = dict(config)
    panel_reference = run(['docker', 'inspect', '--format', '{{.Config.Image}}', config['panel_container']]).decode().strip()
    config['postgres_image'] = run(['docker', 'inspect', '--format', '{{.Image}}', config['database_container']]).decode().strip()
    directory = secure_directory(config['archive_directory'])
    temporary = secure_directory(config['temporary_directory'])
    archive_name = 'warp-db-' + datetime.now(MSK).strftime('%Y%m%d-%H%M%S') + '.7z'
    archive = directory / archive_name
    if archive.exists():
        raise BackupError('Archive name already exists')
    with tempfile.TemporaryDirectory(prefix='run-', dir=temporary) as work_name:
        work = Path(work_name)
        payload = work / 'payload'
        payload.mkdir(mode=0o700)
        sql_file = payload / (archive.stem + '.sql')
        snapshot = export_database(config, sql_file)
        for source, destination in config['runtime_files'].items():
            target = (payload / destination).resolve()
            if payload not in target.parents:
                raise BackupError('Runtime destination escapes payload')
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(source, target)
            target.chmod(0o600)
        metadata = {'created_utc': datetime.now(timezone.utc).isoformat(), 'filename_timezone': 'Europe/Moscow', 'database_counts': snapshot['counts'], 'database_snapshot': snapshot['snapshot'], 'sql_file': sql_file.name, 'panel_image': panel_reference, 'postgres_image': config['postgres_image'], 'files': {str(p.relative_to(payload)): file_hash(p) for p in payload.rglob('*') if p.is_file()}, 'backup_secrets_included': False}
        (payload / 'RESTORE_MANIFEST.json').write_text(json.dumps(metadata, indent=2))
        candidate = work / archive_name
        encrypted = archive_worker(config, 'create', candidate, work, config['archive_password'], source=payload)
        if not encrypted.get('round_trip') or not encrypted.get('headers_encrypted'):
            raise BackupError('Encryption validation failed')
        pending = archive.with_suffix('.7z.pending')
        shutil.copyfile(candidate, pending)
        with pending.open('rb') as data:
            os.fsync(data.fileno())
        os.replace(pending, archive)
        archive.chmod(0o600)
        parts = split_archive(archive, config.get('part_bytes', 16 * 1024 * 1024))
        me = telegram_json(config['telegram_token'], 'getMe', {})
        if me['id'] != config['expected_bot_id']:
            raise BackupError('Telegram bot identity mismatch')
        digest = file_hash(archive)
        receipt = {'archive': archive.name, 'installation_id': config['installation_id'], 'sha256': digest, 'archive_size': archive.stat().st_size, 'delivery_verified': False, 'parts': [], 'created_utc': metadata['created_utc'], 'database_counts': snapshot['counts']}
        receipt_path = archive.with_suffix('.receipt.json')
        receipt_path.write_text(json.dumps(receipt, indent=2))
        receipt_path.chmod(0o600)
        received_parts = []
        for part in parts:
            delivered = send_document(config, part)
            delivered.update({'file_name': part.name, 'sha256': file_hash(part), 'download_verified': False})
            receipt['parts'].append(delivered)
            receipt_path.write_text(json.dumps(receipt, indent=2))
            target = work / ('received-' + part.name)
            download_document(config, delivered['file_id'], target)
            part_hash = file_hash(part)
            if file_hash(target) != part_hash:
                raise BackupError('Downloaded Telegram part checksum mismatch')
            delivered.update({'file_name': part.name, 'sha256': part_hash, 'download_verified': True})
            received_parts.append(target)
            receipt_path.write_text(json.dumps(receipt, indent=2))
        received = work / ('assembled-' + archive_name)
        join_parts(received_parts, received)
        if file_hash(received) != digest:
            raise BackupError('Downloaded Telegram document checksum mismatch')
        restored = work / 'downloaded-restored'
        archive_worker(config, 'extract', received, work, config['archive_password'], output=restored)
        restored_manifest = json.loads((restored / 'RESTORE_MANIFEST.json').read_text())
        for name, expected in restored_manifest['files'].items():
            path = (restored / name).resolve()
            if restored not in path.parents or file_hash(path) != expected:
                raise BackupError('Downloaded payload checksum mismatch')
        receipt.update({key: receipt['parts'][0][key] for key in ('message_id', 'file_id', 'file_unique_id', 'file_size')})
        receipt.update({'delivery_verified': True, 'encrypted_round_trip': True, 'headers_encrypted': True})
        receipt_path.write_text(json.dumps(receipt, indent=2))
        receipt_path.chmod(0o600)
        if verify_restore:
            receipt['independent_restore'] = restore_test(config, work, restored / restored_manifest['sql_file'], restored_manifest['database_counts'])
        receipt_path.write_text(json.dumps(receipt, indent=2))
        receipt_path.chmod(0o600)
        receipt['retention_removed'] = prune_delivered(directory, config.get('keep_delivered', 72), config['installation_id'])
        receipt_path.write_text(json.dumps(receipt, indent=2))
        print(json.dumps(receipt), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='/etc/warp-relay-panel-backup/config.json')
    parser.add_argument('--verify-restore', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    path = Path(args.config)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise BackupError('Backup configuration permissions must be 0600')
    config = json.loads(path.read_text())
    with backup_lock(config['lock_file']) as acquired:
        if not acquired:
            print('Backup already running', flush=True)
            return
        perform(config, args.verify_restore)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        detail = str(error) if isinstance(error, BackupError) else type(error).__name__
        print('Backup failed: ' + detail, file=sys.stderr, flush=True)
        raise SystemExit(1)
