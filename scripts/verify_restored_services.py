"""Verify restored core service access on a private Docker network on Kali."""

import argparse
import json
import os
import re
import secrets
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from backup_lab import run, table_counts
from configure_gateway import read_env
from restore_lab_backup import validate_backup


SERVICES = {
    'sg-gitea': '/data',
    'sg-jenkins': '/var/jenkins_home',
    'sg-grafana': '/var/lib/grafana',
}


def service_archives(metadata):
    """Reject missing/ambiguous mounts before allocating disposable resources."""
    images, mounts = metadata.get('service_images', {}), metadata.get('service_mounts', {})
    archives = {item['source']: item['archive'] for item in metadata['volumes']}
    selected = {}
    for service, destination in SERVICES.items():
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', str(images.get(service, ''))):
            raise ValueError('Missing exact service image: ' + service)
        sources = [item.get('source') for item in mounts.get(service, []) if item.get('destination') == destination]
        if len(sources) != 1 or sources[0] not in archives:
            raise ValueError('Missing or ambiguous persistent mount: ' + service)
        selected[service] = archives[sources[0]]
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup', type=Path)
    parser.add_argument('--output', type=Path, default=Path('reports/restored-service-access.json'))
    args = parser.parse_args()
    directory = args.backup.resolve()
    metadata = validate_backup(directory)
    archives = service_archives(metadata)
    prefix = 'sg-access-' + uuid.uuid4().hex[:12]
    network = prefix + '-network'
    containers, volumes = [], []
    environment = {**os.environ, 'POSTGRES_USER': 'restore_operator', 'POSTGRES_DB': 'restore_lab',
                   'POSTGRES_PASSWORD': secrets.token_urlsafe(32)}
    started = time.monotonic()
    os.umask(0o077)
    result = {'backup_commit': metadata['commit'], 'network_internal': True, 'published_ports': 0}
    try:
        with tempfile.TemporaryDirectory(prefix='sg_recovery_private_') as scratch:
            private = Path(scratch)
            with tarfile.open(directory / 'private-config.tgz') as archive:
                archive.extractall(private, filter='data')
            values = read_env(private / '.env')
            if any(not values.get(key) for key in ('GITEA_TOKEN', 'PROXY_AUTH_USER', 'PROXY_AUTH_PASSWORD', 'GRAFANA_ADMIN_PASSWORD')):
                raise ValueError('Snapshot lacks required private service credentials')
            bootstrap = private / 'secrets/jenkins'
            if not (bootstrap / 'bootstrap.json').is_file():
                raise ValueError('Snapshot lacks the native Jenkins bootstrap configuration')
            quiet = private / 'zzzz-recovery-quiet.groovy'
            quiet.write_text('import jenkins.model.Jenkins\n'
                             'def instance = Jenkins.get()\n'
                             'instance.setNumExecutors(0)\n'
                             'instance.doQuietDown()\n'
                             'instance.save()\n')
            run(['docker', 'network', 'create', '--internal', network])
            def volume(label):
                name = prefix + '-' + label
                run(['docker', 'volume', 'create', name])
                volumes.append(name)
                return name
            def start(label, image, options):
                name = prefix + '-' + label
                containers.append(name)
                run(['docker', 'run', '-d', '--name', name, '--network', network,
                     '--network-alias', label, *options, image], env=environment)
                return name
            database = start('postgres', metadata['postgres_image'], [
                '-e', 'POSTGRES_USER', '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB',
                '-v', volume('database') + ':/var/lib/postgresql/data'])
            for attempt in range(60):
                ready = subprocess.run(['docker', 'exec', database, 'pg_isready', '-U', 'restore_operator', '-d', 'restore_lab'], capture_output=True)
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Restored PostgreSQL startup failed')
            with (directory / 'postgres.dump').open('rb') as dump:
                subprocess.run(['docker', 'exec', '-i', database, 'pg_restore', '--exit-on-error', '--no-owner',
                                '--no-privileges', '-U', 'restore_operator', '-d', 'restore_lab'],
                               stdin=dump, capture_output=True, check=True)
            if table_counts(database) != metadata['table_counts']:
                raise ValueError('Restored table counts differ from snapshot')
            result['matched_tables'] = len(metadata['table_counts'])
            restored = {}
            for service, archive in archives.items():
                restored[service] = volume(service)
                common = ['docker', 'run', '--rm', '--user', '0', '--network', 'none', '--entrypoint', 'tar',
                          '-v', restored[service] + ':/restored', '-v', str(directory) + ':/backup:ro', metadata['archive_image']]
                run([*common, '-xzf', '/backup/' + archive, '-C', '/restored'])
                run([*common, '--compare', '-zf', '/backup/' + archive, '-C', '/restored'])
            environment.update({
                'GITEA__database__DB_TYPE': 'postgres', 'GITEA__database__HOST': 'postgres:5432',
                'GITEA__database__NAME': 'restore_lab', 'GITEA__database__USER': 'restore_operator',
                'GITEA__database__PASSWD': environment['POSTGRES_PASSWORD'],
                'GITEA__server__ROOT_URL': 'http://gitea:3000/', 'GITEA__server__DISABLE_SSH': 'true',
                'GITEA__mailer__ENABLED': 'false', 'GITEA__actions__ENABLED': 'false',
                'GITEA__service__DISABLE_REGISTRATION': 'true',
                'GF_SERVER_ROOT_URL': 'http://grafana:3000/grafana/', 'GF_SERVER_SERVE_FROM_SUB_PATH': 'true',
                'GF_PLUGINS_PREINSTALL': '', 'GF_UNIFIED_ALERTING_ENABLED': 'false',
                'GF_ALERTING_ENABLED': 'false',
            })
            start('gitea', metadata['service_images']['sg-gitea'], [
                *[argument for key in environment if key.startswith('GITEA__') for argument in ('-e', key)],
                '-v', restored['sg-gitea'] + ':/data'])
            start('jenkins', metadata['service_images']['sg-jenkins'], [
                '--user', '0', '-e', 'JENKINS_OPTS=--prefix=/jenkins',
                '-v', restored['sg-jenkins'] + ':/var/jenkins_home',
                '-v', str(bootstrap) + ':/run/secureguard-jenkins:ro',
                '-v', str(quiet) + ':/var/jenkins_home/init.groovy.d/zzzz-recovery-quiet.groovy:ro'])
            start('grafana', metadata['service_images']['sg-grafana'], [
                *[argument for key in environment if key.startswith('GF_') for argument in ('-e', key)],
                '-v', restored['sg-grafana'] + ':/var/lib/grafana',
                '-v', str(private / 'monitoring/grafana/provisioning') + ':/etc/grafana/provisioning:ro',
                '-v', str(private / 'monitoring/grafana/dashboards') + ':/var/lib/grafana/dashboards:ro'])
            # The client has only the restored private network; no ports or Docker socket.
            environment.update({'RESTORE_GITEA_TOKEN': values['GITEA_TOKEN'],
                                'RESTORE_JENKINS_USER': values['PROXY_AUTH_USER'],
                                'RESTORE_JENKINS_PASSWORD': values['PROXY_AUTH_PASSWORD'],
                                'RESTORE_GRAFANA_USER': values.get('GRAFANA_ADMIN_USER', 'admin'),
                                'RESTORE_GRAFANA_PASSWORD': values['GRAFANA_ADMIN_PASSWORD']})
            client_code = '''import os,json,time,base64
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
checks={}
readiness={}
def get(url,headers=None):
 with urlopen(Request(url,headers=headers or {}),timeout=10) as response:return json.load(response)
def basic(user,password):return {'Authorization':'Basic '+base64.b64encode((user+':'+password).encode()).decode()}
for attempt in range(90):
 try:
  repos=get('http://gitea:3000/api/v1/user/repos?limit=100',{'Authorization':'token '+os.environ['RESTORE_GITEA_TOKEN']})
  user=get('http://grafana:3000/grafana/api/user',basic(os.environ['RESTORE_GRAFANA_USER'],os.environ['RESTORE_GRAFANA_PASSWORD']))
  dashboards=get('http://grafana:3000/grafana/api/search?type=dash-db',basic(os.environ['RESTORE_GRAFANA_USER'],os.environ['RESTORE_GRAFANA_PASSWORD']))
  jenkins=get('http://jenkins:8080/jenkins/api/json',basic(os.environ['RESTORE_JENKINS_USER'],os.environ['RESTORE_JENKINS_PASSWORD']))
  readiness={'repositories':len(repos),'dashboards':len(dashboards),'jobs':len(jenkins.get('jobs',[])),
             'grafana_login_present':bool(user.get('login')),
             'quieting_down':jenkins.get('quietingDown'),'executors':jenkins.get('numExecutors')}
  if not (repos and dashboards and jenkins.get('jobs') and user.get('login')
          and jenkins.get('quietingDown') is True and jenkins.get('numExecutors')==0):
   time.sleep(2)
   continue
  try:get('http://jenkins:8080/jenkins/api/json')
  except HTTPError as error:assert error.code in (401,403)
  else:raise AssertionError('Restored Jenkins permits anonymous API access')
  checks={'gitea_repositories':len(repos),'grafana_dashboards':len(dashboards),'jenkins_jobs':len(jenkins['jobs']),'native_authentication':True,'jenkins_execution_disabled':True}
  break
 except (HTTPError,URLError,TimeoutError):time.sleep(2)
else:raise RuntimeError('Restored service access did not become ready: '+json.dumps(readiness))
print(json.dumps(checks))
'''
            containers.append(prefix + '-client')
            inspected_network = json.loads(run(['docker', 'network', 'inspect', network], text=True).stdout)[0]
            if not inspected_network['Internal']:
                raise ValueError('Restore network permits outbound access')
            for name in containers[:-1]:
                item = json.loads(run(['docker', 'inspect', name], text=True).stdout)[0]
                if item['HostConfig'].get('PortBindings') or item['HostConfig'].get('Privileged') or any(
                        mount['Destination'] == '/var/run/docker.sock' for mount in item['Mounts']):
                    raise ValueError('Restore container crossed its isolation boundary')
            client = subprocess.run(['docker', 'run', '--rm', '--network', network, '--entrypoint', 'python',
                                     '--name', prefix + '-client',
                                     *[argument for key in environment if key.startswith('RESTORE_') for argument in ('-e', key)],
                                     '-i', metadata['archive_image'], '-'], env=environment, input=client_code,
                                    text=True, capture_output=True, timeout=300)
            if client.returncode:
                # Retain bounded diagnostics privately before disposing the
                # restored containers. Never print credentials or raw logs.
                diagnostics = args.output.with_suffix('.failure.log')
                diagnostics.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with diagnostics.open('w') as handle:
                    handle.write(client.stderr[-16000:])
                    for name in containers[:-1]:
                        logs = subprocess.run(['docker', 'logs', '--tail', '100', name],
                                              text=True, capture_output=True)
                        handle.write('\n' + name + '\n' + logs.stdout + logs.stderr)
                diagnostics.chmod(0o600)
                raise RuntimeError('Restored service access failed; private diagnostics: ' + str(diagnostics))
            result.update(json.loads(client.stdout))
            result['elapsed_seconds'] = round(time.monotonic() - started, 1)
            args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + '\n')
            print('Restored Gitea/Jenkins/Grafana access: PASS')
            print('Private evidence:', args.output)
    finally:
        for container in reversed(containers):
            subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
        for name in volumes:
            subprocess.run(['docker', 'volume', 'rm', name], capture_output=True)
        subprocess.run(['docker', 'network', 'rm', network], capture_output=True)


if __name__ == '__main__':
    main()
