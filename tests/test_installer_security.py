"""Exercise installer traversal defenses with harmless temporary fixtures on Kali."""

import csv
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from pip._internal.exceptions import InstallationError
from pip._internal.utils.unpacking import untar_file


def fixture_wheel(directory, entrypoint):
    name = 'sg_fixture_pkg'
    dist = name + '-1.0.dist-info'
    wheel = directory / (name + '-1.0-py3-none-any.whl')
    files = {
        name + '.py': b'def main():\n    return None\n',
        dist + '/METADATA': b'Metadata-Version: 2.1\nName: sg-fixture-pkg\nVersion: 1.0\n',
        dist + '/WHEEL': (b'Wheel-Version: 1.0\nGenerator: security-regression-fixture\n'
                         b'Root-Is-Purelib: true\nTag: py3-none-any\n'),
        dist + '/entry_points.txt': ('[console_scripts]\n' + entrypoint
                                     + ' = sg_fixture_pkg:main\n').encode(),
    }
    record = io.StringIO()
    writer = csv.writer(record)
    for path in files:
        writer.writerow([path, '', ''])
    writer.writerow([dist + '/RECORD', '', ''])
    files[dist + '/RECORD'] = record.getvalue().encode()
    with zipfile.ZipFile(wheel, 'w') as archive:
        for name, body in files.items():
            archive.writestr(name, body)
    return wheel


class InstallerSecurityTests(unittest.TestCase):
    def test_wheel_accepts_normal_entrypoint_and_rejects_outside_script(self):
        with tempfile.TemporaryDirectory(prefix='sg_wheel_regression_') as scratch:
            root = Path(scratch)
            prefix = root / 'prefix'
            outside = root / 'outside-install-prefix'

            def install(entrypoint):
                wheel = fixture_wheel(root, entrypoint)
                return subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps',
                     '--no-compile', '--disable-pip-version-check', '--force-reinstall',
                     '--prefix', str(prefix), str(wheel)],
                    capture_output=True, text=True, timeout=30,
                )

            normal = install('sg-fixture')
            self.assertEqual(normal.returncode, 0, normal.stderr)
            self.assertTrue((prefix / 'bin/sg-fixture').is_file())
            malicious = install(str(outside))
            self.assertNotEqual(malicious.returncode, 0)
            self.assertFalse(outside.exists(), 'Wheel entry point escaped installation prefix')

    def test_tar_accepts_normal_file_and_blocks_symlink_write(self):
        with tempfile.TemporaryDirectory(prefix='sg_tar_regression_') as scratch:
            root = Path(scratch)
            outside = root / 'outside-extraction'
            outside.mkdir()
            archive_path = root / 'fixture.tar'
            with tarfile.open(archive_path, 'w') as archive:
                member = tarfile.TarInfo('pkg/normal.txt')
                member.size = 4
                archive.addfile(member, io.BytesIO(b'test'))
            normal = root / 'normal'
            untar_file(str(archive_path), str(normal))
            self.assertEqual((normal / 'normal.txt').read_bytes(), b'test')

            with tarfile.open(archive_path, 'w') as archive:
                member = tarfile.TarInfo('pkg/link')
                member.type = tarfile.SYMTYPE
                member.linkname = str(outside)
                archive.addfile(member)
                member = tarfile.TarInfo('pkg/link/marker')
                member.size = 4
                archive.addfile(member, io.BytesIO(b'test'))
            try:
                untar_file(str(archive_path), str(root / 'malicious'))
            except (InstallationError, tarfile.FilterError):
                pass
            self.assertFalse((outside / 'marker').exists(), 'Archive symlink escaped extraction')


if __name__ == '__main__':
    unittest.main()
