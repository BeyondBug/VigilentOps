"""Server-only notification privacy and delivery outcome checks; all sends mocked."""

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ai-engine'))
from notifier import Notifier


class NotificationTests(unittest.TestCase):
    def test_alert_does_not_copy_secret_descriptions_or_claim_ai_was_queued(self):
        with patch.dict(os.environ, {'SLACK_WEBHOOK_URL': 'https://notification.example/private-key'}, clear=True):
            notifier = Notifier()
        with patch.object(notifier, '_send_slack', return_value=True) as send:
            result = notifier.send_alert('owner/repo', 'a' * 40, [{
                'scanner': 'gitleaks', 'rule_id': 'secret-rule', 'severity': 'HIGH',
                'description': 'fixture-sensitive-value', 'vulnerable_code': 'fixture-sensitive-source',
            }])
        message = send.call_args.args[0]
        self.assertNotIn('fixture-sensitive', message)
        self.assertNotIn('has been queued', message)
        self.assertEqual(result, {'slack': True})

    def test_provider_rejection_is_failure_without_url_or_body_in_logs(self):
        with patch.dict(os.environ, {'SLACK_WEBHOOK_URL': 'https://notification.example/private-key'}, clear=True):
            notifier = Notifier()
        response = httpx.Response(403, text='fixture-sensitive-body',
                                  request=httpx.Request('POST', notifier.slack_webhook))
        with patch('notifier.httpx.Client') as client, self.assertLogs('notifications', level='ERROR') as logs:
            client.return_value.__enter__.return_value.post.return_value = response
            self.assertFalse(notifier._send_slack('Synthetic fixture'))
        messages = ' '.join(logs.output)
        self.assertNotIn('private-key', messages)
        self.assertNotIn('fixture-sensitive-body', messages)

    def test_jira_ticket_omits_raw_finding_description(self):
        notifier = Notifier()
        with patch('notifier.httpx.Client') as client:
            response = client.return_value.__enter__.return_value.post
            self.assertTrue(notifier._create_jira_ticket('repo', {'rule_id': 'B107', 'description': 'fixture-password'}))
        self.assertNotIn('fixture-password', str(response.call_args.kwargs['json']))

    def test_email_starttls_uses_a_verifying_context(self):
        with patch.dict(os.environ, {}, clear=True):
            notifier = Notifier()
        with patch('notifier.smtplib.SMTP') as smtp:
            smtp.return_value.__enter__.return_value.send_message.return_value = {}
            self.assertTrue(notifier._send_email('repo', 'Synthetic fixture'))
        context = smtp.return_value.__enter__.return_value.starttls.call_args.kwargs['context']
        self.assertTrue(context.check_hostname)

    def test_email_recipient_refusal_is_not_success(self):
        notifier = Notifier()
        with patch('notifier.smtplib.SMTP') as smtp:
            smtp.return_value.__enter__.return_value.send_message.return_value = {'recipient': (550, b'rejected')}
            self.assertFalse(notifier._send_email('repo', 'Synthetic fixture'))
