"""Scan exact images in the current Compose stack on Kali; keep reports private."""

import argparse
import json
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from validate_scan_reports import _sarif


def docker_json(arguments):
    return json.loads(subprocess.check_output(['docker', *arguments], text=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--tools', nargs='+', choices=('trivy', 'dockle'), default=['trivy', 'dockle'],
                        help='Rerun a failed tool separately while retaining earlier evidence')
    parser.add_argument('--services', nargs='+', default=[],
                        help='Audit changed Compose services only; omitted means every existing container')
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    ids = subprocess.check_output(['docker', 'compose', '--profile', '*', 'ps', '--all', '--quiet'],
                                  text=True).split()
    if not ids:
        raise ValueError('No Compose containers found; deploy the intended stack before scanning')
    inventory = docker_json(['inspect', *ids])
    if args.services:
        available = {item['Config']['Labels']['com.docker.compose.service'] for item in inventory}
        if not set(args.services) <= available:
            raise ValueError('Requested Compose service is absent from the deployed inventory')
        inventory = [item for item in inventory
                     if item['Config']['Labels']['com.docker.compose.service'] in args.services]
    groups = {}
    for item in inventory:
        image = item['Image']
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            raise ValueError('Container does not reference an exact image ID')
        group = groups.setdefault(image, [])
        group.append({'container': item['Name'].lstrip('/'),
                      'service': item['Config']['Labels']['com.docker.compose.service'],
                      'running': item['State']['Running'], 'reference': item['Config']['Image']})
    selected = json.loads(Path('scanners/images.json').read_text())
    scanners = {tool: docker_json(['image', 'inspect', selected[tool]])[0]['Id']
                for tool in ('trivy', 'dockle')}
    metadata = {'created_at': datetime.now(timezone.utc).isoformat(),
                'checkout': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
                'scope': 'Exact images of existing Compose containers, including stopped services; no source image builds',
                'selected_services': args.services or 'all existing Compose containers',
                'scanner_images': scanners, 'images': []}
    # Retain the feed timestamp. Offline scanning prevents implicit downloads;
    # freshness and applicability still require review in the acceptance record.
    database = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat',
                               '-v', 'trivy-cache:/root/.cache/trivy:ro', scanners['trivy'],
                               '/root/.cache/trivy/db/metadata.json'], capture_output=True, text=True)
    if database.returncode:
        raise ValueError('Preload the persistent Trivy vulnerability database before this scan')
    metadata['trivy_database'] = json.loads(database.stdout)
    failed = False
    for index, (image, services) in enumerate(sorted(groups.items())):
        directory = output / ('image-' + str(index).zfill(3))
        directory.mkdir(mode=0o700)
        record = {'image_id': image, 'services': services, 'reports': {}}
        metadata['images'].append(record)
        for tool in dict.fromkeys(args.tools):
            path = directory / (tool + '.sarif')
            path.touch(mode=0o600)
            name = 'sg-image-audit-' + uuid.uuid4().hex[:16]
            alias = None
            command = ['docker', 'run', '--rm', '--name', name, '--network', 'none',
                       '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                       '--user', str(os.getuid()), '--group-add', str(Path('/var/run/docker.sock').stat().st_gid),
                       '--cpus', '2', '--memory', '4g', '--pids-limit', '512',
                       '-v', '/var/run/docker.sock:/var/run/docker.sock',
                       '-v', str(directory) + ':/reports']
            if tool == 'trivy':
                command += ['-v', 'trivy-cache:/cache:ro', scanners[tool], 'image', '--cache-dir', '/cache',
                            '--image-src', 'docker', '--offline-scan', '--skip-db-update',
                            '--skip-java-db-update', '--cache-backend', 'memory', '--timeout', '15m',
                            '--format', 'sarif', '--output', '/reports/trivy.sarif', image]
            else:
                # Dockle requires a named Docker reference rather than a bare
                # image ID. Create a unique local alias, verify its exact ID,
                # and remove only that alias when this scanner finishes.
                alias = name + ':scan'
                command += [scanners[tool], '-f', 'sarif', '-o', '/reports/dockle.sarif', alias]
            try:
                if alias:
                    subprocess.run(['docker', 'image', 'tag', image, alias], check=True,
                                   capture_output=True)
                    if docker_json(['image', 'inspect', alias])[0]['Id'] != image:
                        raise ValueError('Temporary image alias does not match the inventoried image ID')
                with (directory / (tool + '.log')).open('w') as log:
                    process = subprocess.run(command, stdout=log, stderr=log, timeout=960)
                if process.returncode:
                    raise ValueError('Scanner execution failed with exit ' + str(process.returncode))
                count = _sarif(path)
                record['reports'][tool] = {'status': 'accepted', 'path': str(path.relative_to(output)),
                                          'finding_records': count}
            except (ValueError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as error:
                failed = True
                record['reports'][tool] = {'status': 'failed', 'diagnostic': str(error)}
            finally:
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
                if alias:
                    subprocess.run(['docker', 'image', 'rm', alias], capture_output=True)
            print(image[:19], tool, record['reports'][tool]['status'], flush=True)
        (output / 'inventory.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('Image scope:', len(groups), 'Container scope:', sum(map(len, groups.values())))
    print('Reports are private; accepted scanner output does not mean vulnerabilities are resolved.')
    raise SystemExit(1 if failed else 0)


if __name__ == '__main__':
    main()
