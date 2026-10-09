"""Scan every declared/discovered Docker build artifact and retain exact coverage.

Kali/Jenkins only. Builds still require the configured Docker daemon; this is
coverage orchestration, not a sandbox for executing untrusted build instructions.
"""
import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import uuid
from pathlib import Path
from validate_scan_reports import _sarif

EXCLUDED = {'.git', 'node_modules', 'venv', '.venv', '.tox', '__pycache__'}


def local_path(root, value, directory=False):
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ValueError('Artifact paths must be nonempty repository-relative paths')
    path = root / value
    if '..' in Path(value).parts or any(parent.is_symlink() for parent in [path, *path.parents] if parent != root.parent):
        raise ValueError('Artifact paths cannot escape through traversal or symlinks')
    if not path.resolve().is_relative_to(root.resolve()) or not (path.is_dir() if directory else path.is_file()):
        raise ValueError('Artifact context/Dockerfile is missing or outside the repository')
    return path


def discover(root):
    files = []
    for directory, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in EXCLUDED
                                and not (Path(directory)/name).is_symlink())
        for name in sorted(names):
            path = Path(directory)/name
            if not path.is_symlink() and path.is_file() and (name == 'Dockerfile' or
                    name.startswith('Dockerfile.') or name.endswith('.Dockerfile')):
                files.append(path.relative_to(root).as_posix())
    return sorted(files)


def plan_artifacts(root):
    root = root.resolve()
    discovered = discover(root)
    manifest = root / '.secureguard/artifacts.json'
    if manifest.exists():
        local_path(root, '.secureguard/artifacts.json')
        payload = json.loads(manifest.read_text())
        if not isinstance(payload, dict) or set(payload) != {'schema', 'artifacts'} or payload['schema'] != 1:
            raise ValueError('Invalid artifact manifest')
        items = payload['artifacts']
        origin = 'explicit_manifest'
    else:
        # Inference is visible; projects needing a different context must declare it.
        items = [{'id': 'docker-' + hashlib.sha256(path.encode()).hexdigest()[:12],
                  'dockerfile': path, 'context': str(Path(path).parent)} for path in discovered]
        origin = 'dockerfile_discovery_inferred_context'
    if not isinstance(items, list) or len(items) > 100:
        raise ValueError('Artifact list must contain at most 100 builds')
    seen, builds = set(), []
    for item in items:
        if (not isinstance(item, dict) or set(item) - {'id', 'dockerfile', 'context', 'target', 'services'}
                or not isinstance(item.get('id'), str)
                or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', item['id'])
                or item['id'] in seen):
            raise ValueError('Artifact IDs must be valid and unique')
        context = local_path(root, item.get('context'), directory=True)
        dockerfile = local_path(root, item.get('dockerfile'))
        if not dockerfile.is_relative_to(context):
            raise ValueError('Dockerfile must be inside its declared build context')
        target = item.get('target')
        if target is not None and (not isinstance(target, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', target)):
            raise ValueError('Invalid build target')
        services = item.get('services', [item['id']])
        if not isinstance(services, list) or not services or any(not isinstance(s, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}', s) for s in services):
            raise ValueError('Invalid artifact service mapping')
        seen.add(item['id'])
        builds.append({**item, 'context': context.relative_to(root).as_posix(),
                       'dockerfile': dockerfile.relative_to(root).as_posix(), 'services': services})
    if set(discovered) - {item['dockerfile'] for item in builds}:
        raise ValueError('Manifest omits discovered Dockerfiles; coverage is incomplete')
    return {'schema': 1, 'scope': 'repository_docker_builds', 'origin': origin,
            'discovered_dockerfiles': discovered, 'artifacts': builds}


def attach_image(report, image_id, artifact_ids):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
        raise ValueError('Expected immutable built image ID')
    for run in report['runs']:
        run.setdefault('properties', {}).update(imageName=image_id, artifact_ids=artifact_ids)
    return report['runs']


def scan_image(image_id, alias, tool, image, directory, host_directory):
    name = 'sg-artifact-scan-' + uuid.uuid4().hex[:12]
    path = directory / (tool + '.sarif')
    command = ['docker', 'run', '--rm', '--name', name, '--network', 'none', '--read-only',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--cpus', '2',
               '--memory', '4g', '--pids-limit', '512', '--tmpfs', '/tmp:rw,nosuid,size=256m',
               '--label', 'secureguard.image-scan=true',
               '-v', '/var/run/docker.sock:/var/run/docker.sock', '-v', host_directory + ':/reports']
    if os.getenv('BUILD_TAG'):
        command += ['--label', 'secureguard.build=' + os.environ['BUILD_TAG']]
    if tool == 'trivy-image':
        command += ['-v', 'trivy-cache:/cache:ro', image, 'image', '--cache-dir', '/cache',
                    '--image-src', 'docker', '--offline-scan', '--skip-db-update', '--skip-java-db-update',
                    '--cache-backend', 'memory', '--timeout', '15m', '--format', 'sarif',
                    '--output', '/reports/trivy-image.sarif', image_id]
    else:
        command += [image, '-f', 'sarif', '-o', '/reports/dockle.sarif', alias]
    try:
        with (directory / (tool + '.log')).open('w') as log:
            process = subprocess.run(command, stdout=log, stderr=log, timeout=960)
        if process.returncode:
            raise ValueError('Image scanner execution failed')
        count = _sarif(path)
        return json.loads(path.read_text()), count
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


def run(root, reports, host_reports, scanners, build_timeout=1200):
    plan = plan_artifacts(root)
    evidence = reports / 'artifacts'
    evidence.mkdir(parents=True, exist_ok=True)
    coverage = {**plan, 'status': 'running', 'images': [], 'scanner_image_ids': {}}
    coverage_path = evidence / 'coverage.json'
    def save():
        coverage_path.write_text(json.dumps(coverage, indent=2) + '\n')
    save()
    if not plan['artifacts']:
        coverage['status'] = 'not_applicable'
        save()
        return coverage
    # Expected artifacts require image reports even if any later build fails.
    (reports / 'image-built.marker').write_text('Expected image coverage; not proof of successful builds.\n')
    aliases, groups = [], {}
    try:
        for tool in ('trivy-image', 'dockle'):
            ref = scanners['trivy' if tool == 'trivy-image' else tool]
            coverage['scanner_image_ids'][tool] = subprocess.check_output(
                ['docker', 'image', 'inspect', ref, '--format', '{{.Id}}'], text=True).strip()
        database = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none',
            '--entrypoint', 'cat', '-v', 'trivy-cache:/cache:ro', scanners['trivy'], '/cache/db/metadata.json'], text=True)
        coverage['trivy_database'] = json.loads(database)
        for item in coverage['artifacts']:
            alias = 'sg-artifact-' + uuid.uuid4().hex[:12] + ':scan'
            aliases.append(alias)
            command = ['docker', 'build', '--tag', alias, '--file', str(root/item['dockerfile'])]
            if item.get('target'):
                command += ['--target', item['target']]
            command += [str(root/item['context'])]
            item['status'] = 'building'
            save()
            with (evidence / (item['id'] + '.build.log')).open('w') as log:
                process = subprocess.run(command, stdout=log, stderr=log, timeout=build_timeout)
            if process.returncode:
                item['status'] = 'failed'
                raise ValueError('Declared artifact build failed; image coverage is incomplete')
            image_id = subprocess.check_output(['docker', 'image', 'inspect', alias, '--format', '{{.Id}}'], text=True).strip()
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', image_id):
                raise ValueError('Built artifact has no immutable image identity')
            item.update(status='built', image_id=image_id)
            groups.setdefault(image_id, {'alias': alias, 'artifacts': []})['artifacts'].append(item['id'])
            save()
        merged = {tool: {'version': '2.1.0', 'runs': []} for tool in ('trivy-image', 'dockle')}
        for index, (image_id, group) in enumerate(sorted(groups.items())):
            directory = evidence / ('image-' + str(index))
            directory.mkdir(exist_ok=True)
            record = {'image_id': image_id, 'artifact_ids': group['artifacts'], 'reports': {}}
            coverage['images'].append(record)
            for tool in merged:
                report, count = scan_image(image_id, group['alias'], tool,
                    coverage['scanner_image_ids'][tool], directory,
                    host_reports.rstrip('/') + '/artifacts/' + directory.name)
                merged[tool]['runs'].extend(attach_image(report, image_id, group['artifacts']))
                record['reports'][tool] = {'status': 'accepted', 'finding_count': count}
                save()
        for tool, report in merged.items():
            (reports / (tool + '.sarif')).write_text(json.dumps(report) + '\n')
        for item in coverage['artifacts']:
            item['status'] = 'scanned'
        coverage['status'] = 'complete'
        save()
        print('Artifact coverage:', len(plan['artifacts']), 'builds;', len(groups), 'immutable images; complete')
        return coverage
    except (ValueError, subprocess.SubprocessError, OSError, KeyboardInterrupt):
        coverage['status'] = 'failed'
        save()
        raise
    finally:
        for alias in aliases:
            subprocess.run(['docker', 'image', 'rm', alias], capture_output=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--reports', required=True, type=Path)
    parser.add_argument('--host-reports', required=True)
    parser.add_argument('--scanner-manifest', required=True, type=Path)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    def cancelled(*_):
        raise KeyboardInterrupt('Image scan cancelled')
    signal.signal(signal.SIGTERM, cancelled)
    try:
        if args.plan_only:
            print(json.dumps(plan_artifacts(args.source), indent=2))
        else:
            run(args.source.resolve(), args.reports, args.host_reports, json.loads(args.scanner_manifest.read_text()))
    except (ValueError, subprocess.SubprocessError, OSError, KeyboardInterrupt) as error:
        parser.exit(1, 'Artifact coverage failed: ' + type(error).__name__ + '; inspect restricted coverage/build logs.\n')
