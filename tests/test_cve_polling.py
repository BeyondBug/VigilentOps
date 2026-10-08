"""Bounded pagination and idempotent alert regression tests, without live feeds."""
import importlib.util
import sys
import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'cve-intel'))
spec = importlib.util.spec_from_file_location('cve_poller_regression', Path(__file__).resolve().parents[1] / 'cve-intel/poller.py')
poller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(poller)


class CVEPollingTests(unittest.IsolatedAsyncioTestCase):
    def response(self, payload, status=200):
        return httpx.Response(status, json=payload, request=httpx.Request('GET', poller.NVD_API))

    async def test_fetches_all_pages_using_one_fixed_window(self):
        client = MagicMock()
        client.get = AsyncMock(side_effect=[self.response({'startIndex': 0, 'totalResults': 3, 'vulnerabilities': [{'n': 1}, {'n': 2}]}),
                                            self.response({'startIndex': 2, 'totalResults': 3, 'vulnerabilities': [{'n': 3}]})])
        with patch.object(poller, 'parse_nvd_vulnerability', side_effect=lambda v: v), patch.object(poller.asyncio, 'sleep', new_callable=AsyncMock):
            result = await poller.fetch_nvd_recent(client, datetime.now(timezone.utc))
        self.assertEqual(result, [{'n': 1}, {'n': 2}, {'n': 3}])
        params = [call.kwargs['params'] for call in client.get.call_args_list]
        self.assertEqual([p['startIndex'] for p in params], [0, 2])
        self.assertEqual(params[0]['lastModEndDate'], params[1]['lastModEndDate'])

    async def test_incomplete_page_and_persistent_rate_limits_fail_closed(self):
        for responses in ([self.response({'startIndex': 0, 'totalResults': 3, 'vulnerabilities': []})],
                          [self.response({}, 429)] * 3):
            client = MagicMock()
            client.get = AsyncMock(side_effect=responses)
            with patch.object(poller.asyncio, 'sleep', new_callable=AsyncMock):
                with self.assertRaises((ValueError, httpx.HTTPStatusError)):
                    await poller.fetch_nvd_recent(client, datetime.now(timezone.utc))
            self.assertLessEqual(client.get.call_count, 3)

    async def test_kev_failure_is_distinct_from_successful_empty_catalog(self):
        client = MagicMock()
        client.get = AsyncMock(return_value=self.response({}, 503))
        self.assertIsNone(await poller.fetch_cisa_kev(client))
        client.get = AsyncMock(return_value=self.response({'vulnerabilities': []}))
        self.assertEqual(await poller.fetch_cisa_kev(client), set())

    def test_alert_delivery_has_stable_unique_event_key(self):
        database = MagicMock()
        conn = database.return_value.__enter__.return_value
        cursor = conn.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [(1,), None]
        with patch.object(poller, 'get_db', database):
            self.assertTrue(poller.create_alert('kev', 'CRITICAL', 'title', 'body', event_key='kev:CVE-2026-12345'))
            self.assertFalse(poller.create_alert('kev', 'CRITICAL', 'title', 'body', event_key='kev:CVE-2026-12345'))
        sql, values = cursor.execute.call_args.args
        self.assertIn('ON CONFLICT (event_key) DO NOTHING', sql)
        self.assertEqual(values[-1], 'kev:CVE-2026-12345')
