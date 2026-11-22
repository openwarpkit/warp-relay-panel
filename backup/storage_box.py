from contextlib import contextmanager
from datetime import date, datetime
import errno
import hashlib
import posixpath
import re
import stat

import paramiko


PROJECT = 'warp-relay-panel'
MARKER = '.backup-owner'
ARCHIVE_FILE = re.compile(r'(?:[01][0-9]|2[0-3])[-:][0-5][0-9]\.7z')
DATE_DIRECTORY = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
ARCHIVE_FORMAT = '%Y-%m-%d/%H-%M.7z'


class StorageError(RuntimeError):
    pass


class ExistingArchive(StorageError):
    pass


def parse_archive(archive):
    day, separator, name = archive.partition('/')
    if not separator or not DATE_DIRECTORY.fullmatch(day) or not ARCHIVE_FILE.fullmatch(name):
        raise StorageError('Expected YYYY-MM-DD/HH-MM.7z or YYYY-MM-DD/HH:MM.7z')
    try:
        return datetime.strptime(day + '/' + name.replace(':', '-'), ARCHIVE_FORMAT)
    except ValueError:
        raise StorageError('Invalid archive date') from None


def archive_path(slot):
    return slot.strftime(ARCHIVE_FORMAT)


def alternate_path(archive):
    day, name = archive.split('/')
    alternate = name.replace(':', '-') if ':' in name else name.replace('-', ':')
    return f'{day}/{alternate}'


def lstat(sftp, path):
    try:
        return sftp.lstat(path)
    except OSError as error:
        if error.errno != errno.ENOENT:
            raise
        return None


def directory(sftp, path, create=False):
    entry = lstat(sftp, path)
    if entry is None and create:
        sftp.mkdir(path, mode=0o700)
        entry = sftp.lstat(path)
    if entry is None or not stat.S_ISDIR(entry.st_mode):
        raise StorageError('Expected a real directory in Storage Box')


def digest_stream(source, target=None, limit=None):
    digest = hashlib.sha256()
    size = 0
    while chunk := source.read(256 * 1024):
        size += len(chunk)
        if limit is not None and size > limit:
            raise StorageError('Archive exceeds the configured size limit')
        if target is not None:
            target.write(chunk)
        digest.update(chunk)
    return size, digest.hexdigest()


def read_archive(sftp, path, limit, target=None):
    entry = lstat(sftp, path)
    if entry is None or not stat.S_ISREG(entry.st_mode):
        raise StorageError('Expected a regular archive in Storage Box')
    if not 0 < entry.st_size <= limit:
        raise StorageError('Invalid archive size in Storage Box')
    with sftp.open(path, 'rb') as source:
        source.prefetch(file_size=entry.st_size, max_concurrent_requests=32)
        size, digest = digest_stream(source, target, limit)
    if size != entry.st_size:
        raise StorageError('Storage Box download size mismatch')
    return size, digest


def resolve_archive(sftp, root, archive):
    day = posixpath.join(root, posixpath.dirname(archive))
    directory(sftp, day)
    if lstat(sftp, posixpath.join(root, archive)) is not None:
        return archive
    return alternate_path(archive)


@contextmanager
def connect(config, private_key, known_hosts):
    with paramiko.SSHClient() as client:
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            config['host'], port=config['port'], username=config['user'],
            pkey=paramiko.Ed25519Key.from_private_key_file(str(private_key)),
            allow_agent=False, look_for_keys=False,
            timeout=15, banner_timeout=15, auth_timeout=15, channel_timeout=30,
        )
        with client.open_sftp() as sftp:
            sftp.get_channel().settimeout(30)
            yield sftp


def project_root(sftp, namespace=PROJECT):
    return posixpath.join(sftp.normalize('.'), namespace)


def owner_bytes(server_id):
    return (PROJECT + ':' + server_id + '\n').encode()


def verify_owner(sftp, root, server_id):
    directory(sftp, root)
    marker = posixpath.join(root, MARKER)
    expected = owner_bytes(server_id)
    entry = lstat(sftp, marker)
    if entry is None or not stat.S_ISREG(entry.st_mode) or entry.st_size != len(expected):
        raise StorageError('Storage Box project ownership marker is missing or invalid')
    with sftp.open(marker, 'rb') as source:
        if source.read(len(expected) + 1) != expected:
            raise StorageError('Storage Box project belongs to another installation')


def initialize(sftp, root, server_id):
    directory(sftp, root, create=True)
    names = sftp.listdir(root)
    if names and MARKER not in names:
        raise StorageError('Storage Box project directory is already in use')
    if not names:
        with sftp.open(posixpath.join(root, MARKER), 'wx') as target:
            target.write(owner_bytes(server_id))
    verify_owner(sftp, root, server_id)


def publish(sftp, root, slot, archive):
    relative = archive_path(slot)
    day, name = posixpath.split(posixpath.join(root, relative))
    directory(sftp, day, create=True)
    final = posixpath.join(day, name)
    if lstat(sftp, posixpath.join(root, alternate_path(relative))) is not None:
        raise ExistingArchive('A legacy archive for this hour already exists')
    pending = posixpath.join(day, '.' + name + '.partial')
    with archive.open('rb') as source:
        expected = digest_stream(source)
    published = lstat(sftp, final)
    if published is None:
        entry = lstat(sftp, pending)
        if entry is not None and not stat.S_ISREG(entry.st_mode):
            raise StorageError('Unexpected pending upload in Storage Box')
        sftp.put(str(archive), pending, confirm=True)
        if read_archive(sftp, pending, expected[0]) != expected:
            raise StorageError('Uploaded archive SHA-256 mismatch')
        sftp.rename(pending, final)
        published = lstat(sftp, final)
        if published is None or not stat.S_ISREG(published.st_mode) or published.st_size != expected[0]:
            raise StorageError('Published archive metadata mismatch')
    else:
        if not stat.S_ISREG(published.st_mode):
            raise StorageError('Expected a regular archive in Storage Box')
        if published.st_size != expected[0] or read_archive(sftp, final, expected[0]) != expected:
            raise ExistingArchive('An archive for this hour already exists')
    return expected


def days(sftp, root):
    for entry in sftp.listdir_attr(root):
        if stat.S_ISDIR(entry.st_mode) and DATE_DIRECTORY.fullmatch(entry.filename):
            try:
                day = date.fromisoformat(entry.filename)
            except ValueError:
                continue
            yield day, posixpath.join(root, entry.filename)


def list_archives(sftp, root):
    for _, path in sorted(days(sftp, root), reverse=True):
        directory(sftp, path)
        for entry in sorted(sftp.listdir_attr(path), key=lambda item: item.filename, reverse=True):
            if stat.S_ISREG(entry.st_mode) and ARCHIVE_FILE.fullmatch(entry.filename):
                yield posixpath.relpath(posixpath.join(path, entry.filename), root), entry.st_size


def migration_plan(sftp, root, recorded):
    entries = {}
    legacy = set()
    for _, path in days(sftp, root):
        directory(sftp, path)
        for entry in sftp.listdir_attr(path):
            relative = posixpath.relpath(posixpath.join(path, entry.filename), root)
            entries.setdefault(relative.casefold(), []).append(relative)
            if ':' in entry.filename and ARCHIVE_FILE.fullmatch(entry.filename):
                legacy.add(relative)
    conflicts = []
    moves = []
    for old in sorted(legacy | recorded.keys()):
        new = archive_path(parse_archive(old))
        if new == old:
            raise StorageError(f'Invalid legacy path in migration journal: {old}')
        occupants = entries.get(new.casefold(), [])
        if old in legacy and occupants:
            conflicts.extend(f'{old} -> {target}' for target in sorted(occupants))
        elif old not in legacy and occupants != [new]:
            conflicts.append(f'{old} -> {new} (found: {", ".join(occupants) or "neither path"})')
        else:
            moves.append((old, new, old in legacy))
    if conflicts:
        raise StorageError('Archive name conflicts:\n' + '\n'.join(conflicts))
    return moves


def prune(sftp, root, server_id, cutoff):
    verify_owner(sftp, root, server_id)
    removed = 0
    for day, path in days(sftp, root):
        if day >= cutoff:
            continue
        directory(sftp, path)
        for entry in sftp.listdir_attr(path):
            name = entry.filename
            partial = name.startswith('.') and name.endswith('.partial')
            archive_name = name[1:-8] if partial else name
            if stat.S_ISREG(entry.st_mode) and ARCHIVE_FILE.fullmatch(archive_name):
                sftp.remove(posixpath.join(path, name))
                removed += 1
        if not sftp.listdir(path):
            sftp.rmdir(path)
    return removed
