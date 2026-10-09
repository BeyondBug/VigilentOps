"""Evidence cannot be replaced by severity, scanner agreement or model scores."""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ai-engine'))
import fix_engine
from finding_verification import evidence_confirmed


class VerificationGateTests(unittest.TestCase):
    def fixture(self):
        return {'id': 1, 'scan_run_id': 7, 'commit_sha': 'a'*40, 'file_path': 'app.py',
                'finding_class': 'sast', 'review_status': 'confirmed', 'review_owner': 'Fixture reviewer',
                'review_evidence': 'Controlled reproduction observed a shell execution.',
                'review_details': {'tested_commit': 'a'*40, 'artifact': 'app.py',
                                  'verification_method': 'controlled_reproduction',
                                  'proof_reference': 'private-fixture-proof.log',
                                  'reproduction_steps': 'Run controlled input in the isolated fixture.',
                                  'observed_impact': 'Input reached a command execution sink.'}}

    def test_worker_filters_legacy_confirmation_and_model_confidence(self):
        verified = self.fixture()
        invalid = [{**verified, 'review_details': {}},
                   {**verified, 'review_status': 'unverified', 'confidence': 1.0},
                   {**verified, 'review_details': {**verified['review_details'], 'tested_commit': 'b'*40}},
                   {**verified, 'finding_class': 'quality'}]
        connection = MagicMock()
        cursor = connection.__enter__.return_value.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = [verified, *invalid]
        with patch.object(fix_engine, 'get_db', return_value=connection):
            self.assertEqual(fix_engine.get_all_findings(7), [verified])
            self.assertEqual(fix_engine.get_scan_findings(7), [verified])

    def test_mark_pr_only_updates_evidence_eligible_ids_in_changed_files(self):
        connection = MagicMock()
        cursor = connection.__enter__.return_value.cursor.return_value.__enter__.return_value
        with patch.object(fix_engine, 'get_db', return_value=connection), \
             patch.object(fix_engine, 'get_all_findings', return_value=[self.fixture()]):
            fix_engine.mark_pr_opened(7, 'https://fixture/pr/1', ['app.py'])
        statement, params = cursor.execute.call_args_list[0].args
        self.assertIn('id = ANY(%s)', statement)
        self.assertIn("review_status = 'confirmed'", statement)
        self.assertEqual(params[-1], [1])

    def test_missing_metadata_and_short_or_wrong_evidence_fail_closed(self):
        verified = self.fixture()
        self.assertTrue(evidence_confirmed(verified, 'a'*40))
        for field in ('review_owner', 'review_evidence', 'file_path'):
            self.assertFalse(evidence_confirmed({**verified, field: None}, 'a'*40))
        for key in verified['review_details']:
            details = {name: value for name, value in verified['review_details'].items() if name != key}
            self.assertFalse(evidence_confirmed({**verified, 'review_details': details}, 'a'*40))
        self.assertFalse(evidence_confirmed(verified, 'b'*40))
