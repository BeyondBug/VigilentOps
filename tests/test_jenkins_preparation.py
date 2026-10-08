"""Private bootstrap preparation checks; run on the server."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from prepare_jenkins_security import prepare


class JenkinsPreparationTests(unittest.TestCase):
    def test_account_changes_retain_service_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = Path(temporary) / '.env'
            private = Path(temporary) / 'private'
            env.write_text('PROXY_AUTH_USER=operator\nPROXY_AUTH_PASSWORD=fixture-password\n')
            prepare(env, private)
            before = json.loads((private / 'bootstrap.json').read_text())
            env.write_text('PROXY_AUTH_USER=renamed\nPROXY_AUTH_PASSWORD=changed-fixture\n')
            prepare(env, private)
            after = json.loads((private / 'bootstrap.json').read_text())
            self.assertEqual(after['admin_user'], 'renamed')
            self.assertEqual(after['webhook_token'], before['webhook_token'])
            self.assertEqual(after['metrics_password'], before['metrics_password'])
            self.assertEqual((private / 'bootstrap.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(private.stat().st_mode & 0o777, 0o700)

    def test_gitea_token_is_stored_only_in_private_bootstrap(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as temporary:
            env = Path(temporary) / '.env'
            private = Path(temporary) / 'private'
            env.write_text('PROXY_AUTH_USER=operator\nPROXY_AUTH_PASSWORD=fixture-password\nGITEA_TOKEN=fixture-private-git-token\nGITEA_GIT_USERNAME=fixture-bot\n')
            output = StringIO()
            with redirect_stdout(output):
                prepare(env, private)
            values = json.loads((private / 'bootstrap.json').read_text())
            self.assertEqual(values['gitea_username'], 'fixture-bot')
            self.assertEqual(values['gitea_token'], 'fixture-private-git-token')
            self.assertNotIn('fixture-private-git-token', output.getvalue())
            self.assertEqual((private / 'bootstrap.json').stat().st_mode & 0o777, 0o600)
