from contextlib import nullcontext
from datetime import datetime
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import posixpath
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import hetzner_backup as backup
import storage_box


DAY = '2026-11-22'
OLD = f'{DAY}/11:00.7z'
NEW = f'{DAY}/11-00.7z'
ROOT = '/home/warp-relay-panel'
CONFIG = {'server_id': 'test', 'directory': 'warp-relay-panel', 'host': 'test.example',
          'user': 'test', 'port': 23, 'max_archive_bytes': 1024 * 1024}


class RemoteFile(io.BytesIO):
    def prefetch(self, *, file_size, max_concurrent_requests):
        pass


class MemorySFTP:
    def __init__(self):
        self.directories = {ROOT, f'{ROOT}/{DAY}'}
        self.files = {f'{ROOT}/.backup-owner': storage_box.owner_bytes('test')}
        self.renames = []
        self.reads = []
        self.interrupt = False

    def normalize(self, _):
        return '/home'

    def lstat(self, path):
        if path in self.directories:
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_size=0)
        if path in self.files:
            return SimpleNamespace(st_mode=stat.S_IFREG, st_size=len(self.files[path]))
        raise FileNotFoundError(errno.ENOENT, 'Missing', path)

    def listdir_attr(self, directory):
        names = self.directories | self.files.keys()
        return [
            SimpleNamespace(filename=posixpath.basename(path), **vars(self.lstat(path)))
            for path in sorted(names) if posixpath.dirname(path) == directory
        ]

    def listdir(self, directory):
        return [entry.filename for entry in self.listdir_attr(directory)]

    def mkdir(self, path, mode):
        self.directories.add(path)

    def open(self, path, mode):
        self.reads.append(path)
        return RemoteFile(self.files[path])

    def put(self, source, target, confirm):
        self.files[target] = Path(source).read_bytes()

    def rename(self, old, new):
        if new in self.files or new in self.directories:
            raise FileExistsError(errno.EEXIST, 'Destination exists', new)
        self.renames.append((old, new))
        self.files[new] = self.files.pop(old)
        if self.interrupt:
            self.interrupt = False
            raise OSError('Connection lost after rename')

    def remove(self, path):
        del self.files[path]

    def rmdir(self, path):
        if self.listdir(path):
            raise OSError('Directory is not empty')
        self.directories.remove(path)


class ArchiveNameTests(unittest.TestCase):
    def setUp(self):
        self.state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.sftp = MemorySFTP()
        self.enterContext(patch.object(backup, 'STATE', self.state))
        self.enterContext(patch.object(backup, 'log'))
        self.enterContext(patch.object(storage_box, 'connect', side_effect=lambda *_: nullcontext(self.sftp)))

    def put(self, relative, content=b'archive'):
        self.sftp.files[f'{ROOT}/{relative}'] = content
        return len(content), hashlib.sha256(content).hexdigest()

    def test_new_upload_uses_windows_compatible_name(self):
        source = self.state / 'spool.7z'
        source.write_bytes(b'archive')
        slot = datetime(2026, 11, 22, 11)
        self.assertEqual(storage_box.archive_path(slot), NEW)
        storage_box.publish(self.sftp, ROOT, slot, source)
        self.assertEqual(self.sftp.files[f'{ROOT}/{NEW}'], b'archive')
        self.assertEqual(self.sftp.renames, [(f'{ROOT}/{DAY}/.11-00.7z.partial', f'{ROOT}/{NEW}')])

    def test_publish_recovers_existing_legacy_slot_without_creating_a_second_copy(self):
        self.put(OLD)
        source = self.state / 'spool.7z'
        source.write_bytes(b'candidate')
        with self.assertRaises(storage_box.ExistingArchive):
            storage_box.publish(self.sftp, ROOT, datetime(2026, 11, 22, 11), source)
        self.assertNotIn(f'{ROOT}/{NEW}', self.sftp.files)

    def test_migration_preserves_bytes_and_updates_last_success(self):
        size, digest = self.put(OLD)
        backup.save_status(OLD, size, digest)
        previous = backup.last_success()
        backup.migrate_names(CONFIG, apply=False)
        self.assertEqual(self.sftp.renames, [])
        self.assertFalse((self.state / 'archive-name-migration.json').exists())
        backup.migrate_names(CONFIG, apply=True)
        self.assertEqual(self.sftp.renames, [(f'{ROOT}/{OLD}', f'{ROOT}/{NEW}')])
        self.assertEqual(backup.last_success(), dict(previous, archive=NEW))
        self.assertEqual(storage_box.read_archive(self.sftp, f'{ROOT}/{NEW}', size), (size, digest))
        self.assertTrue(backup.read_state_json('archive-name-migration.json')['complete'])
        backup.migrate_names(CONFIG, apply=True)
        self.assertEqual(len(self.sftp.renames), 1)

    def test_all_collisions_are_reported_before_any_rename(self):
        for name in ('10:00.7z', '11:00.7z', '11-00.7z', '12:00.7z', '12-00.7Z'):
            self.put(f'{DAY}/{name}')
        with self.assertRaises(storage_box.StorageError) as error:
            backup.migrate_names(CONFIG, apply=True)
        self.assertIn(f'{OLD} -> {NEW}', str(error.exception))
        self.assertIn(f'{DAY}/12:00.7z -> {DAY}/12-00.7Z', str(error.exception))
        self.assertEqual(self.sftp.renames, [])
        self.assertFalse((self.state / 'archive-name-migration.json').exists())

    def test_resume_checks_hash_of_rename_committed_before_disconnect(self):
        self.put(OLD)
        next_old = f'{DAY}/12:00.7z'
        next_new = f'{DAY}/12-00.7z'
        self.put(next_old, b'next archive')
        self.sftp.interrupt = True
        with self.assertRaisesRegex(backup.BackupError, 'interrupted'):
            backup.migrate_names(CONFIG, apply=True)
        self.assertFalse(backup.read_state_json('archive-name-migration.json')['complete'])
        self.put(NEW, b'changed')
        with self.assertRaisesRegex(backup.BackupError, 'checksum mismatch'):
            backup.migrate_names(CONFIG, apply=True)
        self.assertIn(f'{ROOT}/{next_old}', self.sftp.files)
        self.put(NEW)
        backup.migrate_names(CONFIG, apply=True)
        self.assertEqual(self.sftp.renames, [(f'{ROOT}/{OLD}', f'{ROOT}/{NEW}'),
                                            (f'{ROOT}/{next_old}', f'{ROOT}/{next_new}')])
        self.assertTrue(backup.read_state_json('archive-name-migration.json')['complete'])

    def test_download_and_restore_accept_both_paths_and_legacy_manifest(self):
        payload = self.state / 'payload'
        payload.mkdir()
        dump = payload / backup.DUMP
        dump.write_bytes(b'snapshot')
        (payload / backup.MANIFEST).write_text(json.dumps({
            'server_id': 'test', 'database': 'warp', 'slot': OLD, 'dump_sha256': backup.file_hash(dump),
        }))
        encrypted = self.state / 'encrypted.7z'
        password = 'test archive password for validation'
        backup.create_archive(encrypted, payload, password)
        size, digest = self.put(OLD, encrypted.read_bytes())
        with patch.object(backup, 'archive_password', return_value=password), patch.dict(os.environ, PGDATABASE='warp'), \
             patch.object(backup, 'command') as pg_restore, patch.object(backup, 'restore_test') as restore:
            for physical in (OLD, NEW):
                if physical == NEW:
                    backup.migrate_names(CONFIG, apply=True)
                for requested in (OLD, NEW):
                    with self.subTest(physical=physical, requested=requested):
                        self.assertEqual(backup.check_archive(CONFIG, requested, restore=True), (physical, size, digest))
                        self.assertEqual(self.sftp.reads[-1], f'{ROOT}/{physical}')
            self.assertEqual(pg_restore.call_count, 4)
            self.assertEqual(restore.call_count, 4)

    def test_retention_matches_both_name_formats(self):
        expired = '2026-10-01'
        self.sftp.directories.add(f'{ROOT}/{expired}')
        self.put(f'{expired}/10:00.7z')
        self.put(f'{expired}/11-00.7z')
        self.put(f'{expired}/notes.txt')
        self.put(NEW)
        self.assertEqual(storage_box.prune(self.sftp, ROOT, 'test', datetime(2026, 10, 24).date()), 2)
        self.assertEqual(dict(storage_box.list_archives(self.sftp, ROOT)), {NEW: 7})
        self.assertIn(f'{ROOT}/{expired}/notes.txt', self.sftp.files)


if __name__ == '__main__':
    unittest.main()
