"""Run pinned Dockerfile/shell linters on Kali/Jenkins and emit required SARIF."""

import argparse
import json
import os
import re
import subprocess
import signal
import uuid
from pathlib import Path, PurePosixPath
from urllib.parse import quote


TOOLS = {
    'hadolint': ('hadolint/hadolint:v2.15.1-debian', '2.15.1'),
    'shellcheck': ('koalaman/shellcheck:v0.11.0', '0.11.0'),
}
EXCLUDED_DIRECTORIES = {'.git', '.venv', 'venv', 'node_modules', '.tox', '__pycache__'}
SHELL_SUFFIXES = {'.sh', '.bash', '.dash', '.ksh', '.bats'}
SHEBANG = re.compile(rb'^#![^\r\n]*\b(?:sh|bash|dash|ksh|ash)(?:\s|$)')


def discover_files(source):
    found = {tool: [] for tool in TOOLS}
    for directory, directories, files in os.walk(source, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in EXCLUDED_DIRECTORIES
                                and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(source).as_posix()
            if name == 'Dockerfile' or name.startswith('Dockerfile.') or name.endswith('.Dockerfile'):
                found['hadolint'].append(relative)
            if path.suffix in SHELL_SUFFIXES:
                found['shellcheck'].append(relative)
            else:
                with path.open('rb') as stream:
                    if SHEBANG.match(stream.read(256)):
                        found['shellcheck'].append(relative)
    return found


def native_findings(tool, payload, exit_code):
    if exit_code not in (0, 1):
        raise ValueError(f'{tool} execution failed with exit code {exit_code}')
    items = payload if tool == 'hadolint' else payload.get('comments') if isinstance(payload, dict) else None
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise ValueError(f'{tool} produced malformed native output')
    if exit_code == 1 and not items:
        raise ValueError(f'{tool} failed without any reported finding')
    return items


def make_report(tool, files, findings):
    image, version = TOOLS[tool]
    selected = set(files)
    rules, results = {}, []
    for item in findings:
        raw_file = item.get('file')
        if not isinstance(raw_file, str):
            raise ValueError(f'{tool} finding has no source path')
        path = raw_file.removeprefix('/src/').removeprefix('./')
        if path not in selected or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts:
            raise ValueError(f'{tool} finding is outside the selected source files')
        native_code = item.get('code')
        code = str(native_code) if tool == 'hadolint' else f'SC{native_code}'
        if not re.fullmatch(r'(?:DL|SC)[0-9]{4}', code):
            raise ValueError(f'{tool} finding has an invalid rule identifier')
        message = item.get('message')
        line, column = item.get('line'), item.get('column', 1)
        level = item.get('level')
        if (not isinstance(message, str) or not message or type(line) is not int or line < 1
                or type(column) is not int or column < 1 or level not in {'error', 'warning', 'info', 'style'}):
            raise ValueError(f'{tool} finding has invalid message/location/severity')
        # Lint severity is not an exploitability or CVSS assessment.
        severity = {'error': 'MEDIUM', 'warning': 'LOW', 'info': 'INFO', 'style': 'INFO'}[level]
        link = (f'https://github.com/hadolint/hadolint/wiki/{code}' if code.startswith('DL')
                else f'https://www.shellcheck.net/wiki/{code}')
        rules[code] = {'id': code, 'shortDescription': {'text': f'{tool} {code}'}, 'helpUri': link}
        results.append({'ruleId': code, 'level': 'error' if level == 'error' else 'warning' if level == 'warning' else 'note',
                        'message': {'text': message}, 'properties': {'severity': severity},
                        'locations': [{'physicalLocation': {'artifactLocation': {'uri': quote(path, safe='/')},
                                      'region': {'startLine': line, 'startColumn': column}}}]})
    return {'version': '2.1.0', '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'runs': [{'tool': {'driver': {'name': tool, 'version': version, 'rules': list(rules.values())}},
                      'results': results, 'invocations': [{'executionSuccessful': True, 'exitCode': 0}],
                      'properties': {'coverage': 'analyzed' if files else 'not_applicable',
                                     'reason': 'Static lint analysis' if files else 'No applicable source files',
                                     'scanned_file_count': len(files), 'scanner_image': image,
                                     'excluded_directories': sorted(EXCLUDED_DIRECTORIES),
                                     'symlinks_followed': False}}]}


def run_tool(tool, files, host_source, host_policy):
    findings = []
    for offset in range(0, len(files), 100):
        batch = files[offset:offset + 100]
        name = 'sg-lint-' + uuid.uuid4().hex
        command = ['docker', 'run', '--rm', '--name', name, '--network', 'none', '--read-only',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '128',
                   '--memory', '512m', '--cpus', '2', '-v', host_source + ':/src:ro', '-w', '/src']
        if os.getenv('BUILD_TAG'):
            command += ['--label', 'secureguard.static-scan=true', '--label', 'secureguard.build=' + os.environ['BUILD_TAG']]
        if tool == 'hadolint':
            command += ['-v', host_policy + ':/policy.yaml:ro', '--entrypoint', '/bin/hadolint', TOOLS[tool][0],
                        '--config', '/policy.yaml', '--disable-ignore-pragma', '--format', 'json']
        else:
            command += ['--entrypoint', '/bin/shellcheck', TOOLS[tool][0], '--norc', '--format', 'json1']
        command += ['--', *['/src/' + path for path in batch]]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=600)
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                raise ValueError(f'{tool} returned no valid JSON report (exit {result.returncode})') from None
            findings.extend(native_findings(tool, payload, result.returncode))
        except subprocess.TimeoutExpired:
            raise ValueError(f'{tool} exceeded its 10-minute batch timeout') from None
        finally:
            # Cancelled Docker clients can leave child containers running.
            try:
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                # Jenkins post cleanup also removes children labeled for this build.
                print(f'WARNING: cleanup could not confirm removal of {name}', flush=True)
    return findings


def main():
    def cancelled(signum, frame):
        raise SystemExit('Static lint task cancelled')
    signal.signal(signal.SIGTERM, cancelled)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--host-source', required=True)
    parser.add_argument('--host-policy', required=True)
    parser.add_argument('--reports', required=True, type=Path)
    args = parser.parse_args()
    if not args.source.is_dir():
        parser.error('Source checkout is missing')
    for path in (args.host_source, args.host_policy):
        if not Path(path).is_absolute() or any(character in path for character in ':\r\n'):
            parser.error('Docker bind paths must be absolute and contain no colon/newline')
    os.umask(0o077)
    args.reports.mkdir(parents=True, exist_ok=True)
    discovered = discover_files(args.source)
    for tool, files in discovered.items():
        output = args.reports / (tool + '.sarif')
        output.unlink(missing_ok=True)
        findings = run_tool(tool, files, args.host_source, args.host_policy) if files else []
        report = make_report(tool, files, findings)
        output.write_text(json.dumps(report) + '\n')
        print(f'{tool}: {len(files)} files, {len(findings)} lint records; '
              + ('analyzed' if files else 'NOT APPLICABLE'))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error))
