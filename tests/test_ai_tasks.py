"""Server-only checks for retry message arguments; no provider/broker access."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ai-engine'))
import tasks
from fix_engine import RateLimitDeferred


class AITaskRetryTests(unittest.TestCase):
    def test_deferred_retry_carries_next_route_in_broker_arguments(self):
        task = tasks.run_ai_fix
        with patch.object(tasks, 'run_ai_fix_engine', side_effect=RateLimitDeferred(120, route_offset=4)), \
             patch.object(task, 'retry', side_effect=RuntimeError('fixture retry')) as retry:
            with self.assertRaisesRegex(RuntimeError, 'fixture retry'):
                task.run(310, 'http://sg-gitea:3000/owner/repo.git', 'fixture-sha')
        self.assertEqual(retry.call_args.kwargs['countdown'], 120)
        self.assertEqual(retry.call_args.kwargs['args'], (310, 'http://sg-gitea:3000/owner/repo.git', 'fixture-sha'))
        self.assertEqual(retry.call_args.kwargs['kwargs'], {'route_offset': 4})

    def test_retry_position_reaches_engine_and_old_three_argument_messages_still_work(self):
        for arguments, expected in (((310, 'fixture-repo', 'fixture-sha'), 0),
                                    ((310, 'fixture-repo', 'fixture-sha', 4), 4)):
            with self.subTest(arguments=arguments), \
                 patch.object(tasks, 'run_ai_fix_engine', return_value={'status': 'no_proposal'}) as engine:
                self.assertEqual(tasks.run_ai_fix.run(*arguments), {'status': 'no_proposal'})
                engine.assert_called_once_with(310, 'fixture-repo', 'fixture-sha', route_offset=expected)
