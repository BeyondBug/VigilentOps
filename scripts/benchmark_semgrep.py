"""Run a labeled Semgrep detection benchmark on Kali without executing fixtures."""
import argparse
import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from urllib.parse import unquote


def score(cases, report):
    if report.get('errors') or not isinstance(report.get('results'), list):
        raise ValueError('Benchmark scanner execution or parsing failed')
    definitions = {}
    for item in cases:
        key = (item['path'], item['rule'])
        if key in definitions or type(item['expected']) is not bool:
            raise ValueError('Duplicate or invalid benchmark case')
        definitions[key] = item['expected']
    if not definitions:
        raise ValueError('Benchmark needs labeled cases')
    observed, unrelated = set(), 0
    for result in report['results']:
        path = unquote(result['path']).removeprefix('/fixtures/')
        rule = result['check_id']
        # Semgrep may prefix rule IDs with the config directory.
        matches = [key for key in definitions if key[0] == path and
                   (rule == key[1] or rule.endswith('.' + key[1]))]
        if matches:
            observed.update(matches)
        else:
            unrelated += 1
    totals, by_rule, mismatches = dict(tp=0, fp=0, tn=0, fn=0), {}, []
    for key, expected in definitions.items():
        actual = key in observed
        bucket = ('tp' if actual else 'fn') if expected else ('fp' if actual else 'tn')
        totals[bucket] += 1
        counts = by_rule.setdefault(key[1], dict(tp=0, fp=0, tn=0, fn=0))
        counts[bucket] += 1
        if actual != expected:
            mismatches.append({'path': key[0], 'rule': key[1], 'expected': expected, 'actual': actual})
    def metrics(counts):
        tp, fp, tn, fn = (counts[key] for key in ('tp', 'fp', 'tn', 'fn'))
        return {**counts, 'precision': tp/(tp+fp) if tp+fp else None,
                'recall': tp/(tp+fn) if tp+fn else None,
                'false_positive_rate': fp/(fp+tn) if fp+tn else None}
    return {'scope': 'labeled_rule_cases_only', 'cases': len(definitions), **metrics(totals),
            'by_rule': {rule: metrics(counts) for rule, counts in sorted(by_rule.items())},
            'mismatches': mismatches, 'unlabeled_alerts': unrelated}


def run(rules, fixtures, host_rules, host_fixtures, image, output, require_pass):
    manifest = json.loads((fixtures / 'cases.json').read_text())
    for case in manifest['cases']:
        path = fixtures / case['path']
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(fixtures.resolve()):
            raise ValueError('Benchmark fixture is missing or escapes its directory')
    image_id = subprocess.check_output(['docker', 'image', 'inspect', image, '--format', '{{.Id}}'], text=True).strip()
    name = 'sg-rule-benchmark-' + uuid.uuid4().hex[:12]
    command = ['docker', 'run', '--rm', '--name', name, '--network', 'none', '--read-only',
               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--cpus', '2',
               '--memory', '2g', '--pids-limit', '256', '--tmpfs', '/tmp:rw,nosuid,size=256m',
               '-e', 'SEMGREP_SEND_METRICS=off', '-e', 'SEMGREP_ENABLE_VERSION_CHECK=0',
               '-e', 'SEMGREP_USER_DATA_FOLDER=/tmp/semgrep', '-v', host_rules + ':/rules:ro',
               '-v', host_fixtures + ':/fixtures:ro', image_id, 'semgrep', 'scan',
               '--config=/rules/secureguard-rules.yaml', '--json', '--metrics=off',
               '--disable-version-check', '--no-git-ignore', '--strict', '/fixtures']
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if process.returncode != 0:
            raise ValueError('Benchmark scanner failed; no accuracy score is valid')
        result = score(manifest['cases'], json.loads(process.stdout))
    finally:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    digest = hashlib.sha256()
    for path in sorted(rules.rglob('*')):
        if path.is_file() and not path.is_symlink():
            digest.update(path.relative_to(rules).as_posix().encode() + b'\0' + path.read_bytes())
    result.update(scanner_image_id=image_id, rules_sha256=digest.hexdigest(),
                  fixtures_sha256=hashlib.sha256((fixtures/'cases.json').read_bytes() + b''.join(
                      (fixtures/case['path']).read_bytes() for case in manifest['cases'])).hexdigest())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('cases', 'tp', 'fp', 'tn', 'fn', 'precision', 'recall')}))
    if require_pass and result['mismatches']:
        raise ValueError('Labeled rule benchmark regressed; inspect benchmark output')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rules', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--host-rules', required=True)
    parser.add_argument('--host-fixtures', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-pass', action='store_true')
    args = parser.parse_args()
    try:
        run(args.rules, args.fixtures, args.host_rules, args.host_fixtures, args.image, args.output, args.require_pass)
    except (ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Benchmark failed: ' + type(error).__name__ + '\n')
