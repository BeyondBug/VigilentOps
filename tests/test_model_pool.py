"""Server-only pool configuration, cooldown and request-budget checks."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ai-engine'))
import fix_engine
from model_pool import load_model_pool, RouteCooldowns


class ModelPoolTests(unittest.TestCase):
    def test_numbered_routes_after_nine_and_nim_allowlist_are_ordered_and_deduplicated(self):
        endpoint = 'https://integrate.api.nvidia.com/v1/chat/completions'
        models = load_model_pool({'MODEL_12': 'example/twelve', 'API_KEY_12': 'secret', 'API_URL_12': endpoint,
                                 'MODEL_2': 'example/two', 'API_KEY_2': 'secret', 'API_URL_2': endpoint,
                                 'NVIDIA_NIM_API_KEY': 'secret',
                                 'NVIDIA_NIM_MODELS': 'example/two, example/backup'})
        self.assertEqual([route['model'] for route in models], ['example/two', 'example/twelve', 'example/backup'])

    def test_empty_credentials_disable_provider_calls(self):
        self.assertEqual(load_model_pool({'NVIDIA_NIM_MODELS': 'example/model', 'NVIDIA_NIM_API_KEY': ''}), [])

    def test_endpoint_and_pool_size_are_validated_without_leaking_keys(self):
        for endpoint in ('https://sensitive-secret@provider.example/v1/chat/completions',
                         'https://provider.example/v1/chat/completions?key=sensitive-secret'):
            with self.assertRaises(ValueError) as caught:
                load_model_pool({'MODEL_1': 'example/model', 'API_KEY_1': 'sensitive-secret', 'API_URL_1': endpoint})
            self.assertNotIn('sensitive-secret', str(caught.exception))
        with self.assertRaisesRegex(ValueError, '32'):
            load_model_pool({'NVIDIA_NIM_API_KEY': 'secret',
                             'NVIDIA_NIM_MODELS': ','.join(f'example/model-{n}' for n in range(33))})

    def test_cooldown_expires_and_does_not_extend_shorter_retry(self):
        pool = RouteCooldowns()
        route = {'model': 'example/model', 'key': 'secret', 'url': 'https://provider.example/chat/completions'}
        with patch('model_pool.time.monotonic', return_value=100):
            pool.defer(route, 90)
            pool.defer(route, 5)
            self.assertEqual(pool.remaining(route), 90)
        with patch('model_pool.time.monotonic', return_value=191):
            self.assertEqual(pool.remaining(route), 0)
        self.assertEqual(pool.deadlines, {})

    def test_cooling_route_is_skipped_and_independent_fallback_can_succeed(self):
        routes = [{'model': name, 'key': name, 'url': f'https://{name}.example/chat/completions'}
                  for name in ('first', 'second')]
        with patch.object(fix_engine, 'MODELS', routes), \
             patch.object(fix_engine, 'MODEL_COOLDOWNS', RouteCooldowns()), \
             patch.object(fix_engine, 'call_llm', side_effect=[fix_engine.RateLimitDeferred(120), "print('safe')\n"]) as call:
            self.assertEqual(fix_engine.try_with_fallback('app.py', "print('old')\n", [])[1], 'second')
            call.reset_mock(side_effect=True)
            call.return_value = "print('safe')\n"
            self.assertEqual(fix_engine.try_with_fallback('app.py', "print('old')\n", [])[1], 'second')
            self.assertEqual(call.call_count, 1)
            self.assertEqual(call.call_args.args[1], 'second')

    def test_route_budget_bounds_attempts_even_for_invalid_code(self):
        routes = [{'model': str(n), 'key': 'key', 'url': 'https://provider.example/chat/completions'} for n in range(8)]
        with patch.object(fix_engine, 'MODELS', routes), \
             patch.object(fix_engine, 'MAX_MODEL_ROUTES_PER_FILE', 2), \
             patch.object(fix_engine, 'MODEL_COOLDOWNS', RouteCooldowns()), \
             patch.object(fix_engine, 'call_llm', return_value='invalid ???') as call:
            self.assertEqual(fix_engine.try_with_fallback('app.py', 'pass\n', []), ('', ''))
            self.assertEqual(call.call_count, 2)

    def test_nonfinite_retry_after_values_use_bounded_backoff(self):
        for value in ('nan', 'inf', '-inf'):
            self.assertTrue(1 <= fix_engine._retry_delay(value, 0) <= 3600)
