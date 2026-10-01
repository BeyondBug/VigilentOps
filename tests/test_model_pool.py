"""Server-only pool configuration, cooldown and request-budget checks."""

import sys
import unittest
import httpx
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ai-engine'))
import fix_engine
from model_pool import load_model_pool, RouteCooldowns, OPENROUTER_FREE_MODELS, OPENROUTER_URL


class ModelPoolTests(unittest.TestCase):
    def test_only_approved_openrouter_routes_are_loaded_despite_old_provider_credentials(self):
        models = load_model_pool({'OPENROUTER_API_KEY': 'fixture-key',
                                 'MODEL_1': 'openai/gpt-4o', 'API_KEY_1': 'old-key',
                                 'API_URL_1': OPENROUTER_URL, 'NVIDIA_NIM_API_KEY': 'old-key',
                                 'NVIDIA_NIM_MODELS': 'example/other', 'PRIMARY_API_KEY': 'old-key'})
        self.assertEqual([route['model'] for route in models], list(OPENROUTER_FREE_MODELS))
        self.assertTrue(all(route['url'] == OPENROUTER_URL and route['key'] == 'fixture-key' for route in models))

    def test_subset_order_and_duplicate_removal_do_not_add_other_models(self):
        first, second = OPENROUTER_FREE_MODELS[:2]
        routes = load_model_pool({'OPENROUTER_API_KEY': 'key', 'OPENROUTER_MODELS': f'{second}, {first},{second}'})
        self.assertEqual([route['model'] for route in routes], [second, first])
        self.assertEqual(load_model_pool({'OPENROUTER_API_KEY': 'key', 'OPENROUTER_MODELS': ''}), [])

    def test_empty_credentials_disable_provider_calls(self):
        self.assertEqual(load_model_pool({'OPENROUTER_API_KEY': '', 'NVIDIA_NIM_API_KEY': 'old-key',
                                         'PRIMARY_API_KEY': 'old-key'}), [])

    def test_paid_unapproved_and_secret_like_model_ids_are_rejected_without_leaking_values(self):
        for model in ('openai/gpt-4o', OPENROUTER_FREE_MODELS[0].removesuffix(':free'),
                      'example/not-approved:free', 'sensitive-secret'):
            with self.assertRaises(ValueError) as caught:
                load_model_pool({'OPENROUTER_API_KEY': 'sensitive-secret', 'OPENROUTER_MODELS': model})
            self.assertNotIn('sensitive-secret', str(caught.exception))

    def test_openrouter_http_request_enforces_zero_prices_and_rejects_paid_models_before_http(self):
        model = OPENROUTER_FREE_MODELS[0]
        response = httpx.Response(200, json={'choices': [{'message': {'content': "print('safe')\n"},
                                                         'finish_reason': 'stop'}]},
                                  request=httpx.Request('POST', OPENROUTER_URL))
        with patch.object(fix_engine.httpx, 'post', return_value=response) as request:
            self.assertEqual(fix_engine.call_llm('fixture', model, OPENROUTER_URL, 'key'), "print('safe')")
        self.assertEqual(request.call_args.kwargs['json']['provider']['max_price'],
                         {'prompt': 0, 'completion': 0, 'request': 0})
        with patch.object(fix_engine.httpx, 'post') as request:
            with self.assertRaises(ValueError):
                fix_engine.call_llm('fixture', 'openai/gpt-4o', OPENROUTER_URL, 'key')
        request.assert_not_called()

    def test_openrouter_exhausted_account_quota_defers_without_retrying_all_models(self):
        routes = load_model_pool({'OPENROUTER_API_KEY': 'key'})
        response = httpx.Response(429, headers={'Retry-After': '120', 'X-RateLimit-Remaining': '0'},
                                  request=httpx.Request('POST', OPENROUTER_URL))
        with patch.object(fix_engine, 'MODELS', routes), \
             patch.object(fix_engine, 'MODEL_COOLDOWNS', RouteCooldowns()), \
             patch.object(fix_engine.httpx, 'post', return_value=response) as request, \
             patch.object(fix_engine.time, 'sleep') as sleep:
            with self.assertRaises(fix_engine.RateLimitDeferred):
                fix_engine.try_with_fallback('app.py', "print('old')\n", [])
            self.assertTrue(all(fix_engine.MODEL_COOLDOWNS.remaining(route) > 0 for route in routes))
        request.assert_called_once()
        sleep.assert_not_called()

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
