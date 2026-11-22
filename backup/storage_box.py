from contextlib import contextmanager
from datetime import date
import errno
import hashlib
import posixpath
import re
import stat

import paramiko


PROJECT = 'warp-relay-panel'
MARKER = '.backup-owner'
HOUR_FILE = re.compile(r'(?:[01][0-9]|2[0-3]):00\.7z')
DATE_DIRECTORY = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')


class StorageError(RuntimeError):
    pass


class ExistingArchive(StorageError):
    pass


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
    day = posixpath.join(root, slot.strftime('%Y-%m-%d'))
    directory(sftp, day, create=True)
    name = slot.strftime('%H:00.7z')
    final = posixpath.join(day, name)
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
            if stat.S_ISREG(entry.st_mode) and HOUR_FILE.fullmatch(entry.filename):
                yield posixpath.relpath(posixpath.join(path, entry.filename), root), entry.st_size


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
            if stat.S_ISREG(entry.st_mode) and HOUR_FILE.fullmatch(archive_name):
                sftp.remove(posixpath.join(path, name))
                removed += 1
        if not sftp.listdir(path):
            sftp.rmdir(path)
    return removed
