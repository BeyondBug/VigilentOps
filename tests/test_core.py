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


if __name__ == "__main__":
    unittest.main()
