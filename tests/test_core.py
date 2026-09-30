import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, os.path.join(ROOT, "ai-engine"))

from llm_response import extract_llm_content


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
