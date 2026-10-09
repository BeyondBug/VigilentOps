"""Accuracy scoring and image coverage failure contracts; run on Kali only."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from benchmark_semgrep import score
from run_image_artifacts import plan_artifacts, run, scan_image
from validate_scan_reports import validate_image_coverage


class BenchmarkTests(unittest.TestCase):
    def test_scoring_counts_cases_once_and_reports_all_outcomes(self):
        cases = [dict(path=f'{i}.py', rule='rule', expected=i < 2) for i in range(4)]
        report = {'results': [dict(path='/fixtures/0.py', check_id='rules.rule')]*2 +
                  [dict(path='/fixtures/2.py', check_id='rule'), dict(path='other.py', check_id='other')]}
        result = score(cases, report)
        self.assertEqual([result[k] for k in ('tp', 'fp', 'tn', 'fn')], [1, 1, 1, 1])
        self.assertEqual(result['precision'], .5)
        self.assertEqual(result['recall'], .5)
        self.assertEqual(result['false_positive_rate'], .5)
        self.assertEqual(result['unlabeled_alerts'], 1)
        self.assertEqual(len(result['mismatches']), 2)

    def test_absent_denominator_is_unknown(self):
        result = score([dict(path='safe.py', rule='rule', expected=False)], {'results': []})
        self.assertIsNone(result['precision'])
        self.assertIsNone(result['recall'])
        self.assertEqual(result['false_positive_rate'], 0)

    def test_scanner_errors_never_produce_accuracy_score(self):
        with self.assertRaises(ValueError):
            score([dict(path='safe.py', rule='rule', expected=False)], {'results': [], 'errors': ['parse failed']})

    def test_duplicate_labels_are_rejected(self):
        case = dict(path='safe.py', rule='rule', expected=False)
        with self.assertRaises(ValueError):
            score([case, case], {'results': []})


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root/'source'
        self.source.mkdir()
        self.reports = self.root/'reports'
        self.reports.mkdir()

    def dockerfile(self, path):
        destination = self.source/path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text('FROM scratch\n')

    def manifest(self, artifacts):
        path = self.source/'.secureguard/artifacts.json'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(dict(schema=1, artifacts=artifacts)))

    def test_discovers_all_nested_builds_and_excludes_dependency_fixtures(self):
        for path in ('Dockerfile', 'api/Dockerfile.dev', 'path with spaces/test.Dockerfile', 'node_modules/Dockerfile'):
            self.dockerfile(path)
        (self.source/'linked.Dockerfile').symlink_to(self.source/'Dockerfile')
        plan = plan_artifacts(self.source)
        self.assertEqual(plan['discovered_dockerfiles'], ['Dockerfile', 'api/Dockerfile.dev', 'path with spaces/test.Dockerfile'])
        self.assertEqual(len(plan['artifacts']), 3)

    def test_explicit_context_and_multiple_targets_are_preserved(self):
        self.dockerfile('api/Dockerfile')
        self.manifest([dict(id=target, context='.', dockerfile='api/Dockerfile', target=target, services=[target])
                       for target in ('web', 'worker')])
        plan = plan_artifacts(self.source)
        self.assertEqual([a['target'] for a in plan['artifacts']], ['web', 'worker'])
        self.assertTrue(all(a['context'] == '.' for a in plan['artifacts']))

    def test_manifest_cannot_silently_omit_dockerfile(self):
        self.dockerfile('Dockerfile')
        self.manifest([])
        with self.assertRaises(ValueError):
            plan_artifacts(self.source)

    def test_manifest_rejects_traversal_and_symlink_context(self):
        self.dockerfile('Dockerfile')
        for context in ('../source', 'linked'):
            (self.source/'linked').symlink_to(self.source, target_is_directory=True) if context == 'linked' else None
            self.manifest([dict(id='web', context=context, dockerfile='Dockerfile')])
            with self.assertRaises(ValueError):
                plan_artifacts(self.source)

    def test_failed_build_is_retained_as_incomplete(self):
        self.dockerfile('Dockerfile')
        with patch('run_image_artifacts.subprocess.check_output', side_effect=['sha256:'+'a'*64, 'sha256:'+'b'*64, '{}']), \
             patch('run_image_artifacts.subprocess.run', return_value=subprocess.CompletedProcess([], 1)) as commands:
            with self.assertRaises(ValueError):
                run(self.source, self.reports, str(self.reports), {'trivy':'trivy:fixed','dockle':'dockle:fixed'})
        coverage = json.loads((self.reports/'artifacts/coverage.json').read_text())
        self.assertEqual(coverage['status'], 'failed')
        self.assertEqual(coverage['artifacts'][0]['status'], 'failed')
        self.assertTrue((self.reports/'image-built.marker').exists())
        self.assertFalse((self.reports/'trivy-image.sarif').exists())
        self.assertEqual(commands.call_args.args[0][:3], ['docker','image','rm'])
        with self.assertRaises(ValueError):
            validate_image_coverage(self.reports, required=True)

    def test_success_exit_without_new_report_rejects_stale_result(self):
        (self.reports/'dockle.sarif').write_text(json.dumps({'version':'2.1.0','runs':[{'results':[]}]}))
        with patch('run_image_artifacts.docker_socket_group', return_value=998), \
             patch('run_image_artifacts.subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as commands:
            with self.assertRaises(ValueError):
                scan_image('sha256:'+'a'*64, 'alias:scan', 'dockle', 'scanner:fixed', self.reports, str(self.reports))
        self.assertFalse((self.reports/'dockle.sarif').exists())
        command = commands.call_args_list[0].args[0]
        self.assertIn('--user', command)
        self.assertEqual(command[command.index('--group-add')+1], '998')

    def test_identical_builds_are_scanned_once_per_image_and_map_every_artifact(self):
        for name in ('api/Dockerfile', 'worker/Dockerfile', 'ui/Dockerfile'):
            self.dockerfile(name)
        image_a, image_b = 'sha256:'+'a'*64, 'sha256:'+'b'*64
        identities = ['sha256:'+'c'*64, 'sha256:'+'d'*64, '{}', image_a, image_b, image_a]
        def scanner(*args):
            return {'version':'2.1.0','runs':[{'results':[]}]}, 0
        with patch('run_image_artifacts.subprocess.check_output', side_effect=identities), \
             patch('run_image_artifacts.subprocess.run', return_value=subprocess.CompletedProcess([], 0)), \
             patch('run_image_artifacts.scan_image', side_effect=scanner) as scans:
            coverage = run(self.source, self.reports, str(self.reports), {'trivy':'trivy:fixed','dockle':'dockle:fixed'})
        self.assertEqual(scans.call_count, 4)
        self.assertEqual(len(coverage['artifacts']), 3)
        self.assertEqual(len(coverage['images']), 2)
        self.assertEqual(sorted(len(image['artifact_ids']) for image in coverage['images']), [1, 2])
        self.assertIn('3 artifacts / 2 immutable images', validate_image_coverage(self.reports, True))

    def valid_coverage(self):
        images, artifacts, runs = [], [], []
        for number in range(2):
            image = 'sha256:' + str(number+1)*64
            ids = ['web', 'worker'] if number == 0 else ['frontend']
            artifacts += [dict(id=id, status='scanned', image_id=image) for id in ids]
            images.append(dict(image_id=image, artifact_ids=ids, reports={
                tool:dict(status='accepted', finding_count=0) for tool in ('trivy-image','dockle')}))
            runs.append(dict(results=[], properties=dict(imageName=image, artifact_ids=ids)))
        coverage = dict(schema=1, status='complete', artifacts=artifacts, images=images)
        for tool in ('trivy-image','dockle'):
            (self.reports/(tool+'.sarif')).write_text(json.dumps(dict(version='2.1.0', runs=runs)))
        return coverage

    def save_coverage(self, payload):
        path = self.reports/'artifacts/coverage.json'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(payload))

    def test_accepts_deduplicated_complete_image_identity_and_zero_results(self):
        self.save_coverage(self.valid_coverage())
        self.assertIn('3 artifacts / 2 immutable images', validate_image_coverage(self.reports, True))

    def test_missing_image_run_is_incomplete(self):
        self.save_coverage(self.valid_coverage())
        path = self.reports/'dockle.sarif'
        report = json.loads(path.read_text())
        report['runs'].pop()
        path.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            validate_image_coverage(self.reports, True)

    def test_rejects_tampered_inventory(self):
        valid = self.valid_coverage()
        mutations = [lambda c:c.update(status='failed'),
                     lambda c:c['images'][0]['reports'].pop('dockle'),
                     lambda c:c['images'][0].update(artifact_ids=[{}]),
                     lambda c:c['images'][0].update(image_id='sha256:'+'z'*64),
                     lambda c:c['artifacts'][0].update(image_id='sha256:'+'9'*64),
                     lambda c:c['images'][0]['reports']['dockle'].update(finding_count=1)]
        for mutate in mutations:
            payload = copy.deepcopy(valid)
            mutate(payload)
            self.save_coverage(payload)
            with self.assertRaises(ValueError):
                validate_image_coverage(self.reports, True)

    def test_no_artifacts_is_explicit_not_applicable_and_clears_old_reports(self):
        for name in ('image-built.marker','trivy-image.sarif','dockle.sarif'):
            (self.reports/name).write_text('stale')
        result = run(self.source, self.reports, str(self.reports), {})
        self.assertEqual(result['status'], 'not_applicable')
        self.assertIn('NOT APPLICABLE', validate_image_coverage(self.reports, True))
        self.assertFalse((self.reports/'image-built.marker').exists())

    def test_required_inventory_cannot_be_omitted(self):
        with self.assertRaises(ValueError):
            validate_image_coverage(self.reports, True)
