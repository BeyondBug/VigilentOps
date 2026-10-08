"""Create a private, consistent lab backup on Kali while persistent writers pause."""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import tarfile
import base64
import ssl
from pathlib import Path
from urllib.request import Request, urlopen
from configure_gateway import read_env


VOLUME_CONTAINERS = ('sg-gitea', 'sg-jenkins', 'sg-grafana', 'sg-prometheus', 'sg-wazuh', 'sg-loki', 'sg-redis')
WRITERS = ('sg-celery', 'sg-cve-worker', 'sg-orchestrator', 'sg-cve-intel', 'sg-promtail', *VOLUME_CONTAINERS)


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, capture_output=True, **kwargs)


def table_counts(container):
    query = "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename;"
    def sql(statement):
        return run(['docker', 'exec', '-i', container, 'sh', '-c',
                    'export PGPASSWORD="$POSTGRES_PASSWORD"; exec psql -w -v ON_ERROR_STOP=1 -At -U "$POSTGRES_USER" -d "$POSTGRES_DB"'],
                   input=statement, text=True).stdout.strip()
    return {table: int(sql('SELECT COUNT(*) FROM public."' + table.replace('"', '""') + '";'))
            for table in sql(query).splitlines()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    env = read_env(Path('.env'))
    if env.get('GITEA_DB_NAME', 'secureguard') != env.get('POSTGRES_DB'):
        raise ValueError('This lab backup requires Gitea and findings in the same configured database; back up separate databases explicitly')
    os.umask(0o077)
    directory = (args.output or Path.home() / 'secureguard-backups' /
                 ('lab-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))).resolve()
    checkout = Path.cwd().resolve()
    if directory == checkout or checkout in directory.parents:
        raise ValueError('Private backups must be outside the Git checkout')
    if directory.exists():
        raise ValueError('Choose a new backup directory; existing snapshots are never overwritten')
    directory.mkdir(mode=0o700, parents=True)
    inspected = json.loads(run(['docker', 'inspect', 'sg-postgres', *WRITERS], text=True).stdout)
    running = [item['Name'].lstrip('/') for item in inspected if item['State']['Running']
               and item['Name'].lstrip('/') in WRITERS]
    postgres = next(item for item in inspected if item['Name'] == '/sg-postgres')
    archiver = next(item for item in inspected if item['Name'] == '/sg-orchestrator')
    metadata = {'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'commit': run(['git', 'rev-parse', 'HEAD'], text=True).stdout.strip(),
                'postgres_image': postgres['Image'], 'archive_image': archiver['Image'],
                'volumes': [], 'checksums': {},
                'service_images': {item['Name'].lstrip('/'): item['Image'] for item in inspected},
                'service_mounts': {item['Name'].lstrip('/'): [
                    {'source': mount['Name'], 'destination': mount['Destination']}
                    for mount in item['Mounts'] if mount['Type'] == 'volume'
                ] for item in inspected}}
    # Refuse to interrupt a running/queued pipeline. The helper authenticates
    # through the same HTTPS gateway and native Jenkins account.
    if 'sg-jenkins' in running:
        auth = base64.b64encode((env['PROXY_AUTH_USER'] + ':' + env['PROXY_AUTH_PASSWORD']).encode()).decode()
        request = Request(env['PUBLIC_URL'] + '/jenkins/job/secureguard-shadowpatch/api/json?tree=lastBuild[building],queueItem[id]',
                          headers={'Authorization': 'Basic ' + auth})
        context = ssl.create_default_context(cafile='secrets/gateway/ca.pem')
        with urlopen(request, context=context, timeout=20) as response:
            state = json.load(response)
        if state.get('lastBuild', {}).get('building') or state.get('queueItem'):
            raise ValueError('Let the Jenkins pipeline and queue finish before a consistent backup')
    for worker in ('sg-celery', 'sg-cve-worker'):
        if worker in running:
            for kind in ('active', 'reserved', 'scheduled'):
                reply = json.loads(run(['docker', 'exec', worker, 'celery', '-A', 'tasks',
                                        'inspect', kind, '--timeout', '5', '--json'], text=True).stdout)
                if any(reply.values()):
                    raise ValueError('Let Celery active/reserved/deferred work finish before the backup')
    try:
        if running:
            run(['docker', 'stop', '--time', '60', *running])
        dump = directory / 'postgres.dump'
        with dump.open('wb') as output:
            subprocess.run(['docker', 'exec', 'sg-postgres', 'sh', '-c',
                            'export PGPASSWORD="$POSTGRES_PASSWORD"; exec pg_dump -w -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc'],
                           stdout=output, stderr=subprocess.PIPE, check=True)
        metadata['table_counts'] = table_counts('sg-postgres')
        volumes = sorted({mount['Name'] for item in inspected
                          if item['Name'].lstrip('/') in VOLUME_CONTAINERS
                          for mount in item['Mounts'] if mount['Type'] == 'volume'})
        for index, volume in enumerate(volumes):
            archive = f'volume-{index}.tgz'
            # Root must read volume contents, but keep the output owned by the
            # invoking operator so host-side permission/checksum steps work.
            (directory / archive).touch(mode=0o600)
            run(['docker', 'run', '--rm', '--user', '0', '--network', 'none', '--entrypoint', 'tar',
                 '-v', volume + ':/source:ro', '-v', str(directory) + ':/backup',
                 archiver['Image'], '-czf', '/backup/' + archive, '-C', '/source', '.'])
            metadata['volumes'].append({'source': volume, 'archive': archive})
        with tarfile.open(directory / 'private-config.tgz', 'w:gz') as archive:
            for name in ('.env', 'secrets', 'docker-compose.yml', 'proxy', 'jenkins', 'monitoring'):
                path = Path(name)
                if path.exists():
                    archive.add(path, arcname=name)
        for path in directory.iterdir():
            path.chmod(0o600)
            digest = hashlib.sha256()
            with path.open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(block)
            metadata['checksums'][path.name] = digest.hexdigest()
        (directory / 'manifest.json').write_text(json.dumps(metadata, indent=2) + '\n')
        print('Private backup:', directory)
        print('Volume archives:', len(volumes))
        print('Run restore_lab_backup.py against this snapshot; backup creation is not recovery evidence')
    finally:
        if running:
            run(['docker', 'start', *running])


if __name__ == '__main__':
    main()
