import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "ai-engine"))

from llm_response import extract_llm_content, LLMProviderError


class LLMResponseTests(unittest.TestCase):
    def test_openai_object_response(self):
        data = {"choices": [{"message": {"content": "fixed()"}}]}
        self.assertEqual(extract_llm_content(data), "fixed()")

    def test_gemini_array_response(self):
        data = [{"choices": [{"message": {"content": "```python\nfixed()\n```"}}]}]
        self.assertEqual(extract_llm_content(data), "fixed()")

    def test_empty_content_is_rejected(self):
        with self.assertRaises(ValueError):
            extract_llm_content({"choices": [{"message": {}}]})

    def test_provider_error_rejects_partial_content_at_both_envelope_locations(self):
        choice = {'message': {'content': "print('partial')"}, 'finish_reason': 'stop'}
        error = {'code': 503, 'metadata': {'error_type': 'provider_overloaded'}}
        for data in ({'error': error, 'choices': [choice]},
                     {'choices': [{**choice, 'error': error}]},
                     [{'error': error}]):
            with self.subTest(data=data), self.assertRaises(LLMProviderError) as caught:
                extract_llm_content(data)
            self.assertEqual(caught.exception.status_code, 503)
            self.assertEqual(caught.exception.error_type, 'provider_overloaded')

    def test_error_categories_and_codes_are_normalized_without_provider_text(self):
        secret = 'fixture-sensitive-provider-text'
        cases = [({'code': '429'}, 429, 'unknown'),
                 ({'metadata': {'error_type': 'rate_limit_exceeded'}}, 429, 'rate_limit_exceeded'),
                 ({'code': 'context_length_exceeded'}, 400, 'context_length_exceeded'),
                 ({'code': True, 'metadata': []}, 502, 'unknown'),
                 ({'code': 200, 'error_type': [secret]}, 502, 'unknown'),
                 ({'code': secret, 'metadata': {'error_type': secret}}, 502, 'unknown')]
        for fields, status, category in cases:
            with self.subTest(fields=fields), self.assertRaises(LLMProviderError) as caught:
                extract_llm_content({'error': {**fields, 'message': secret}})
            error = caught.exception
            self.assertEqual((error.status_code, error.error_type), (status, category))
            self.assertNotIn(secret, str(error))
            self.assertNotIn(secret, repr(error.__dict__))

    def test_null_error_fields_allow_complete_successful_content(self):
        self.assertEqual(extract_llm_content({'error': None, 'choices': [
            {'error': None, 'finish_reason': 'stop', 'message': {'content': 'pass'}}]}), 'pass')

    def test_truncated_filtered_tool_calls_and_refusals_are_rejected(self):
        for reason in ('length', 'content_filter', 'tool_calls'):
            with self.assertRaises(ValueError):
                extract_llm_content({'choices': [{'finish_reason': reason,
                    'message': {'content': "print('incomplete')"}}]})
        for message in ({'content': [], 'refusal': 'cannot comply'},
                        {'content': 'pass', 'tool_calls': [{'id': 'unsupported'}]},
                        {'content': ['unexpected structured content']}):
            with self.assertRaises(ValueError):
                extract_llm_content({'choices': [{'message': message}]})


if __name__ == "__main__":
    unittest.main()
