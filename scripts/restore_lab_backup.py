"""Restore a lab snapshot into disposable containers/volumes, never live data."""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path

from backup_lab import run, table_counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup', type=Path)
    args = parser.parse_args()
    directory = args.backup.resolve()
    metadata = json.loads((directory / 'manifest.json').read_text())
    for name, expected in metadata['checksums'].items():
        if Path(name).name != name:
            raise ValueError('Manifest archive paths must be filenames')
        digest = hashlib.sha256()
        with (directory / name).open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ValueError('Backup checksum failed: ' + name)
    prefix = 'sg-restore-' + uuid.uuid4().hex[:12]
    database = prefix + '-postgres'
    volumes = []
    started = time.monotonic()
    environment = {**os.environ, 'POSTGRES_USER': 'restore_operator',
                   'POSTGRES_DB': 'restore_lab', 'POSTGRES_PASSWORD': secrets.token_urlsafe(32)}
    try:
        db_volume = prefix + '-database'
        run(['docker', 'volume', 'create', db_volume])
        volumes.append(db_volume)
        run(['docker', 'run', '-d', '--name', database, '--network', 'none',
             '-e', 'POSTGRES_USER', '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB',
             '-v', db_volume + ':/var/lib/postgresql/data', metadata['postgres_image']], env=environment)
        for attempt in range(60):
            ready = subprocess.run(['docker', 'exec', database, 'pg_isready', '-U', 'restore_operator', '-d', 'restore_lab'], capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Isolated PostgreSQL did not become ready')
        with (directory / 'postgres.dump').open('rb') as dump:
            subprocess.run(['docker', 'exec', '-i', database, 'pg_restore', '--exit-on-error',
                            '--no-owner', '--no-privileges', '-U', 'restore_operator', '-d', 'restore_lab'],
                           stdin=dump, capture_output=True, check=True)
        if table_counts(database) != metadata['table_counts']:
            raise ValueError('Restored database table counts differ from snapshot')
        for index, item in enumerate(metadata['volumes']):
            name = item['archive']
            if name not in metadata['checksums']:
                raise ValueError('Volume archive lacks a verified checksum')
            volume = prefix + '-volume-' + str(index)
            run(['docker', 'volume', 'create', volume])
            volumes.append(volume)
            common = ['docker', 'run', '--rm', '--user', '0', '--network', 'none', '--entrypoint', 'tar',
                      '-v', volume + ':/restored', '-v', str(directory) + ':/backup:ro', metadata['archive_image']]
            run([*common, '-xzf', '/backup/' + name, '-C', '/restored'])
            run([*common, '--compare', '-zf', '/backup/' + name, '-C', '/restored'])
        print('Isolated database restore and volume content comparison: PASS')
        print('Tables:', len(metadata['table_counts']), 'Volumes:', len(metadata['volumes']))
        print('Elapsed seconds:', round(time.monotonic() - started, 1))
        print('This drill does not verify restored service logins or a complete application recovery')
    finally:
        subprocess.run(['docker', 'rm', '-f', database], capture_output=True)
        for volume in volumes:
            subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)


if __name__ == '__main__':
    main()
