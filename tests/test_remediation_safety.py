"""Regression checks for AI remediation proposals."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "ai-engine"))

import fix_engine


class RemediationSafetyTests(unittest.TestCase):
    def test_aliases_of_one_file_produce_one_change(self):
        repo = tempfile.mkdtemp()
        Path(repo, "app.py").write_text("pass\n")
        findings = [
            {"file_path": "/src/app.py", "scanner": "bandit", "branch": "main"},
            {"file_path": "file:///src/app.py", "scanner": "semgrep", "branch": "main"},
        ]
        with (
            patch.object(fix_engine, "get_all_findings", return_value=findings),
            patch.object(fix_engine, "clone_repo", return_value=repo),
            patch.object(fix_engine, "try_with_fallback", return_value=("print('fixed')\n", "model")) as model,
            patch.object(fix_engine, "commit_and_push", return_value=True),
            patch.object(fix_engine, "open_pr", return_value="http://gitea/pr/1") as open_pr,
            patch.object(fix_engine, "mark_pr_opened") as mark_pr,
        ):
            result = fix_engine.run_ai_fix_engine(1, "http://gitea/repo.git", "sha")

        self.assertEqual(model.call_count, 1)
        self.assertEqual(result["files_changed"], 1)
        self.assertEqual(len(open_pr.call_args.args[3]), 1)
        self.assertEqual(
            set(mark_pr.call_args.args[2]),
            {"/src/app.py", "file:///src/app.py"},
        )

    def test_proposal_is_work_in_progress(self):
        with patch.object(fix_engine.httpx, "post") as request:
            request.return_value.status_code = 201
            request.return_value.json.return_value = {"html_url": "http://gitea/pr/1"}
            fix_engine.open_pr(
                "http://gitea/owner/repo.git", "fix-branch", 1,
                [{"file_path": "app.py", "num_vulns": 1,
                  "scanners": ["bandit"], "model": "model"}], "model",
            )
        payload = request.call_args.kwargs["json"]
        self.assertTrue(payload["title"].startswith("WIP:"))
        self.assertIn("unverified", payload["body"])
        self.assertNotIn("vulnerabilities fixed", payload["body"])


if __name__ == "__main__":
    unittest.main()
