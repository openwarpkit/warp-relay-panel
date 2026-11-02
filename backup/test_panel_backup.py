import json
from pathlib import Path
import tempfile
import unittest

import panel_backup as backup


class BackupRetentionTests(unittest.TestCase):
    def test_only_verified_archives_of_this_installation_are_pruned(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            for number in range(75):
                archive = root / ('warp-db-20260101-' + str(number).zfill(6) + '.7z')
                archive.write_bytes(str(number).encode())
                archive.with_suffix('.receipt.json').write_text(json.dumps({'installation_id': 'owned', 'delivery_verified': True, 'sha256': backup.file_hash(archive)}))
            unsent = root / 'warp-db-20250101-000000.7z'
            unsent.write_bytes(b'not delivered')
            foreign = root / 'warp-db-20250102-000000.7z'
            foreign.write_bytes(b'another installation')
            foreign.with_suffix('.receipt.json').write_text(json.dumps({'installation_id': 'other', 'delivery_verified': True, 'sha256': backup.file_hash(foreign)}))
            unrelated = root / 'unrelated.db'
            unrelated.write_bytes(b'preserve')
            self.assertEqual(backup.prune_delivered(root, 72, 'owned'), 3)
            self.assertTrue(unsent.exists())
            self.assertTrue(foreign.exists())
            self.assertTrue(unrelated.exists())
            self.assertFalse((root / 'warp-db-20260101-000000.7z').exists())
            self.assertTrue((root / 'warp-db-20260101-000074.7z').exists())

    def test_small_parts_reassemble_exactly_and_foreign_part_paths_are_preserved(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            archive = root / 'warp-db-20260101-000000.7z'
            original = bytes(range(251)) * 7
            archive.write_bytes(original)
            parts = backup.split_archive(archive, 113)
            self.assertGreater(len(parts), 1)
            self.assertTrue(all(p.stat().st_size <= 113 for p in parts))
            output = root / 'assembled'
            backup.join_parts(parts, output)
            self.assertEqual(output.read_bytes(), original)
            outside = root / 'preserve.txt'
            outside.write_bytes(b'not a backup part')
            archive.with_suffix('.receipt.json').write_text(json.dumps({'installation_id': 'owned', 'delivery_verified': True, 'sha256': backup.file_hash(archive), 'parts': [{'file_name': 'preserve.txt', 'sha256': backup.file_hash(outside)}]}))
            self.assertEqual(backup.prune_delivered(root, 0, 'owned'), 0)
            self.assertTrue(outside.exists())
            self.assertTrue(archive.exists())

    def test_receipt_symlink_is_never_followed_for_retention(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            archive = root / 'warp-db-20260101-000000.7z'
            archive.write_bytes(b'archive')
            outside = root / 'outside.json'
            outside.write_text(json.dumps({'installation_id': 'owned', 'delivery_verified': True, 'sha256': backup.file_hash(archive)}))
            archive.with_suffix('.receipt.json').symlink_to(outside)
            self.assertEqual(backup.prune_delivered(root, 0, 'owned'), 0)
            self.assertTrue(outside.exists())
            self.assertTrue(archive.exists())


if __name__ == '__main__':
    unittest.main()
