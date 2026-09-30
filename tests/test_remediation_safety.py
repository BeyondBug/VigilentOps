"""Regression checks for AI remediation proposals."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "ai-engine"))

import fix_engine
from fix_validation import preserves_python_interface, validates_security_change
from pr_findings import build_finding_comments
from model_pool import RouteCooldowns


class RemediationSafetyTests(unittest.TestCase):
    def setUp(self):
        cooldowns = patch.object(fix_engine, 'MODEL_COOLDOWNS', RouteCooldowns())
        cooldowns.start()
        self.addCleanup(cooldowns.stop)

    def test_clone_rejects_untrusted_origin_port_and_path_before_git(self):
        with patch.object(fix_engine.subprocess, 'run') as git:
            for url in ('http://attacker.example:3000/owner/repo.git',
                        'http://sg-gitea:8000/owner/repo.git',
                        'http://token@sg-gitea:3000/owner/repo.git',
                        'http://sg-gitea:3000/../repo.git',
                        'http://sg-gitea:3000/owner/repo.git?redirect=evil'):
                self.assertIsNone(fix_engine.clone_repo(url))
        git.assert_not_called()

    def test_authenticated_git_uses_private_askpass_without_token_in_argv(self):
        with patch.object(fix_engine, 'GITEA_TOKEN', 'fixture-sensitive-token'), patch.object(fix_engine.subprocess, 'run') as command:
            fix_engine.authenticated_git(['clone', 'http://sg-gitea:3000/owner/repo.git', '/tmp/fixture'])
        self.assertNotIn('fixture-sensitive-token', ' '.join(command.call_args.args[0]))
        self.assertEqual(command.call_args.kwargs['env']['SG_GIT_TOKEN'], 'fixture-sensitive-token')
        self.assertFalse(Path(command.call_args.kwargs['env']['GIT_ASKPASS']).exists())

    def test_bandit_rejects_ineffective_fix_and_suppression(self):
        original = 'import subprocess\ndef execute(command):\n    return subprocess.call(command, shell=True)\n'
        findings = [{"scanner": "bandit", "rule_id": "B602"}]
        for proposed in (original.replace('command', 'cmd'), original.replace('shell=True)', 'shell=True)  # nosec')):
            valid, reason = validates_security_change(original, proposed, findings)
            self.assertFalse(valid)
            self.assertIn("B602", reason)

    def test_bandit_accepts_removed_rule_but_rejects_new_high_issue(self):
        original = 'import subprocess\ndef execute(command):\n    return subprocess.call(command, shell=True)\n'
        proposed = original.replace('shell=True', 'shell=False')
        findings = [{"scanner": "bandit", "rule_id": "B602"}]
        self.assertTrue(validates_security_change(original, proposed, findings)[0])
        self.assertFalse(validates_security_change(original, proposed + '\nvalue = eval(user_input)\n', findings)[0])

    def test_candidate_cannot_remove_or_rename_python_interface(self):
        original = 'def fetch(url, *, timeout=10):\n    return url\n'
        self.assertTrue(preserves_python_interface(original, original.replace('return url', 'return str(url)')))
        self.assertFalse(preserves_python_interface(original, original.replace('fetch(url', 'fetch(target')))
        self.assertFalse(preserves_python_interface(original, 'pass\n'))

    def test_pr_uses_scanned_base_branch(self):
        with patch.object(fix_engine.httpx, "post") as request:
            request.return_value.status_code = 201
            request.return_value.json.return_value = {"html_url": "http://gitea/pr/1"}
            fix_engine.open_pr("http://gitea/owner/repo.git", "fix-branch", 1, [], "model", [], base_branch="master")
        self.assertEqual(request.call_args.kwargs["json"]["base"], "master")

    def test_rate_limit_honors_retry_after_without_busy_retry(self):
        response = httpx.Response(
            429, headers={"Retry-After": "120"},
            request=httpx.Request("POST", "https://model.example/chat"),
        )
        with (
            patch.object(fix_engine.httpx, "post", return_value=response) as request,
            patch.object(fix_engine.time, "sleep") as sleep,
        ):
            with self.assertRaises(fix_engine.RateLimitDeferred) as caught:
                fix_engine.call_llm("prompt", "model", "https://model.example/chat", "key")
        self.assertEqual(caught.exception.retry_after, 120)
        request.assert_called_once()
        sleep.assert_not_called()

    def test_invalid_model_output_tries_next_model(self):
        models = [
            {"model": "first", "key": "one", "url": "https://one.example/chat"},
            {"model": "second", "key": "two", "url": "https://two.example/chat"},
        ]
        with (
            patch.object(fix_engine, "MODELS", models),
            patch.object(fix_engine, "call_llm", side_effect=["not python ???", "print('safe')\n"]) as call,
        ):
            content, model = fix_engine.try_with_fallback("app.py", "print('old')\n", [])
        self.assertEqual((content, model), ("print('safe')\n", "second"))
        self.assertEqual(call.call_count, 2)

    def test_all_rate_limited_models_defer_task(self):
        models = [{"model": "limited", "key": "one", "url": "https://one.example/chat"}]
        with (
            patch.object(fix_engine, "MODELS", models),
            patch.object(fix_engine, "call_llm", side_effect=fix_engine.RateLimitDeferred(90)),
        ):
            with self.assertRaises(fix_engine.RateLimitDeferred) as caught:
                fix_engine.try_with_fallback("app.py", "pass\n", [])
        self.assertEqual(caught.exception.retry_after, 90)

    def test_no_configured_model_skips_before_database_or_clone(self):
        with (
            patch.object(fix_engine, "MODELS", []),
            patch.object(fix_engine, "get_all_findings") as findings,
            patch.object(fix_engine, "clone_repo") as clone,
        ):
            result = fix_engine.run_ai_fix_engine(1, "http://gitea/repo.git", "sha")
        self.assertEqual(result["status"], "skipped")
        findings.assert_not_called()
        clone.assert_not_called()

    def test_aliases_of_one_file_produce_one_change(self):
        repo = tempfile.mkdtemp()
        Path(repo, "app.py").write_text("pass\n")
        findings = [
            {"id": 1, "file_path": "/src/app.py", "scanner": "bandit", "branch": "main"},
            {"id": 2, "file_path": "file:///src/app.py", "scanner": "semgrep", "branch": "main"},
        ]
        with (
            patch.object(fix_engine, "MODELS", [{"model": "model", "key": "test", "url": "http://unused"}]),
            patch.object(fix_engine, "get_all_findings", return_value=findings),
            patch.object(fix_engine, "get_scan_findings", return_value=[
                {"id": 1, "scanner": "bandit", "finding_class": "sast",
                 "severity": "HIGH", "title": "Issue", "file_path": "app.py"},
            ]),
            patch.object(fix_engine, 'get_scan_reports', return_value=[]),
            patch.object(fix_engine, "clone_repo", return_value=repo),
            patch.object(fix_engine, "try_with_fallback", return_value=("print('fixed')\n", "model")) as model,
            patch.object(fix_engine, "commit_and_push", return_value=True),
            patch.object(fix_engine, "open_pr", return_value=("http://gitea/pr/1", True)) as open_pr,
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
                  "scanners": ["bandit"], "model": "model"}], "model", [],
            )
        payload = request.call_args.kwargs["json"]
        self.assertTrue(payload["title"].startswith("WIP:"))
        self.assertIn("unverified", payload["body"])
        self.assertNotIn("vulnerabilities fixed", payload["body"])

    def test_conversation_contains_every_tool_finding_and_redacts_secrets(self):
        findings = [
            {"id": 10, "scanner": "bandit", "finding_class": "sast",
             "severity": "HIGH", "rule_id": "B602", "title": "Shell injection",
             "description": "Untrusted command", "file_path": "app.py",
             "line_start": 12, "fix_status": "open"},
            {"id": 11, "scanner": "trivy-image", "finding_class": "sca",
             "severity": "MEDIUM", "cve_id": "CVE-2026-1234",
             "title": "Library issue", "description": "Upgrade library",
             "file_path": "image", "fix_status": "open"},
            {"id": 12, "scanner": "gitleaks", "finding_class": "secret",
             "severity": "HIGH", "title": "Token", "description": "secret-value",
             "file_path": "config.py", "fix_status": "open"},
            {"id": 13, "scanner": "bandit", "finding_class": "sast",
             "severity": "LOW", "rule_id": "B105", "title": "Hardcoded password",
             "description": "Possible hardcoded password: leaked-value",
             "file_path": "settings.py", "fix_status": "open"},
            {"id": 14, "scanner": "hadolint", "finding_class": "quality",
             "severity": "MEDIUM", "rule_id": "DL1000", "title": "hadolint DL1000",
             "description": "Unexpected token parser-sensitive-value",
             "file_path": "Dockerfile", "fix_status": "open"},
        ]
        comments = build_finding_comments(7, findings, {10})
        conversation = "\n".join(comments)
        for finding_id in (10, 11, 12, 13, 14):
            self.assertIn(f"Finding #{finding_id}", conversation)
        self.assertIn("Proposed file change", conversation)
        self.assertIn("No proposed change", conversation)
        self.assertIn("CVE-2026-1234", conversation)
        self.assertNotIn("secret-value", conversation)
        self.assertNotIn("leaked-value", conversation)
        self.assertNotIn("parser-sensitive-value", conversation)
        self.assertTrue(all(len(comment.encode()) < 25_000 for comment in comments))

    def test_large_scan_is_split_without_losing_findings(self):
        findings = [
            {"id": index, "scanner": "trivy-image", "finding_class": "sca",
             "severity": "HIGH", "title": "Package issue",
             "description": "x" * 1800, "file_path": "image"}
            for index in range(1, 81)
        ]
        comments = build_finding_comments(9, findings, set())
        conversation = "\n".join(comments)
        self.assertGreater(len(comments), 2)
        self.assertTrue(all(len(comment.encode()) < 25_000 for comment in comments))
        for index in range(1, 81):
            self.assertEqual(conversation.count(f"#### Finding #{index} —"), 1)

    def test_conversation_includes_report_coverage_even_for_zero_findings(self):
        comments = build_finding_comments(9, [], set(), [{'tool': 'osv', 'finding_count': 0, 'coverage': 'not_applicable'}])
        self.assertIn('osv: 0 records; NOT APPLICABLE', '\n'.join(comments))

    def test_pr_posts_findings_to_its_conversation(self):
        created = {"html_url": "http://gitea/owner/repo/pulls/4", "number": 4}
        with patch.object(fix_engine.httpx, "post") as request:
            request.side_effect = [
                type("Response", (), {"status_code": 201, "json": lambda self: created})(),
                type("Response", (), {"status_code": 201})(),
            ]
            url, complete = fix_engine.open_pr(
                "http://gitea/owner/repo.git", "fix-branch", 7,
                [{"file_path": "app.py", "num_vulns": 1,
                  "scanners": ["bandit"], "model": "model"}],
                "model", ["Finding details"],
            )
        self.assertEqual(url, created["html_url"])
        self.assertTrue(complete)
        self.assertEqual(request.call_count, 2)
        self.assertIn("/issues/4/comments", request.call_args.args[0])
        self.assertEqual(request.call_args.kwargs["json"]["body"], "Finding details")

    def test_failed_finding_comment_marks_publication_incomplete(self):
        created = {"html_url": "http://gitea/owner/repo/pulls/4", "number": 4}
        with patch.object(fix_engine.httpx, "post") as request:
            request.side_effect = [
                type("Response", (), {"status_code": 201, "json": lambda self: created})(),
                type("Response", (), {"status_code": 503})(),
            ]
            url, complete = fix_engine.open_pr(
                "http://gitea/owner/repo.git", "fix-branch", 7,
                [{"file_path": "app.py", "num_vulns": 1,
                  "scanners": ["bandit"], "model": "model"}],
                "model", ["Finding details"],
            )
        self.assertEqual(url, created["html_url"])
        self.assertFalse(complete)


if __name__ == "__main__":
    unittest.main()
