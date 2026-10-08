"""Restore preflight checks; prepare here, run on Kali."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from restore_lab_backup import validate_backup


class BackupManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        checksums = {}
        for name in ('postgres.dump', 'private-config.tgz', 'volume-0.tgz'):
            content = ('fixture ' + name).encode()
            (self.directory / name).write_bytes(content)
            checksums[name] = hashlib.sha256(content).hexdigest()
        self.manifest = {
            'postgres_image': 'sha256:' + 'a' * 64,
            'archive_image': 'sha256:' + 'b' * 64,
            'table_counts': {'findings': 1},
            'volumes': [{'source': 'fixture-volume', 'archive': 'volume-0.tgz'}],
            'checksums': checksums,
        }

    def validate(self):
        (self.directory / 'manifest.json').write_text(json.dumps(self.manifest))
        return validate_backup(self.directory)

    def test_complete_manifest_passes_preflight(self):
        self.assertEqual(self.validate()['table_counts'], {'findings': 1})

    def test_unverified_database_and_volume_are_rejected(self):
        del self.manifest['checksums']['postgres.dump']
        with self.assertRaises(ValueError):
            self.validate()
        self.manifest['checksums']['postgres.dump'] = hashlib.sha256((self.directory / 'postgres.dump').read_bytes()).hexdigest()
        del self.manifest['checksums']['volume-0.tgz']
        with self.assertRaises(ValueError):
            self.validate()

    def test_corrupted_artifact_is_rejected(self):
        (self.directory / 'postgres.dump').write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'checksum failed'):
            self.validate()

    def test_manifest_cannot_use_unpinned_images_or_path_traversal(self):
        self.manifest['postgres_image'] = 'postgres:latest'
        with self.assertRaises(ValueError):
            self.validate()
        self.manifest['postgres_image'] = 'sha256:' + 'a' * 64
        self.manifest['checksums']['../outside'] = 'a' * 64
        with self.assertRaises(ValueError):
            self.validate()


class PasswordAuthenticatedBackupTests(unittest.TestCase):
    def test_table_inventory_authenticates_without_password_in_host_arguments(self):
        import backup_lab
        from unittest.mock import patch, Mock
        with patch.object(backup_lab, 'run', side_effect=[Mock(stdout='findings\n'), Mock(stdout='3\n')]) as command:
            self.assertEqual(backup_lab.table_counts('fixture-postgres'), {'findings': 3})
        for call in command.call_args_list:
            shell = call.args[0][-1]
            self.assertIn('PGPASSWORD="$POSTGRES_PASSWORD"', shell)
            self.assertIn('psql -w', shell)
            self.assertNotIn('fixture-secret-password', ' '.join(call.args[0]))
