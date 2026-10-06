import re


FENCE_RE = re.compile(
    r"^\s*```[a-zA-Z0-9_+.\-]*\s*\n(.*?)\n\s*```\s*$",
    re.DOTALL,
)

# Only normalized categories may reach logs; provider messages/metadata can
# contain source, credentials or arbitrary upstream text.
PROVIDER_ERROR_STATUSES = {
    'rate_limit_exceeded': 429,
    'provider_overloaded': 503,
    'provider_unavailable': 502,
    'timeout': 504,
    'server': 500,
    'authentication': 401,
    'permission_denied': 403,
    'payment_required': 402,
    'context_length_exceeded': 400,
    'max_tokens_exceeded': 400,
    'invalid_request': 400,
    'refusal': 403,
    'content_policy_violation': 403,
}


class LLMProviderError(ValueError):
    """An error envelope, including those sent after HTTP 200 headers."""

    def __init__(self, error):
        status = None
        category = 'unknown'
        if isinstance(error, dict):
            code = error.get('code')
            if type(code) is int and 400 <= code <= 599:
                status = code
            elif isinstance(code, str) and re.fullmatch(r'[45][0-9]{2}', code):
                status = int(code)
            metadata = error.get('metadata')
            error_type = metadata.get('error_type') if isinstance(metadata, dict) else None
            if error_type is None:
                error_type = error.get('error_type', code)
            if isinstance(error_type, str) and error_type in PROVIDER_ERROR_STATUSES:
                category = error_type
        self.error_type = category
        self.status_code = status or PROVIDER_ERROR_STATUSES.get(category, 502)
        super().__init__(f'Model provider error {self.status_code} ({category})')


def unfence(text: str) -> str:
    match = FENCE_RE.match(text.strip())
    return match.group(1) if match else text.strip()


def extract_llm_content(data) -> str:
    """Extract text from object or one-element-array chat responses."""
    if isinstance(data, list):
        if not data:
            print(f"DEBUG: empty response {data}"); raise ValueError("LLM returned an empty response")
        data = data[0]
    if not isinstance(data, dict):
        print(f"DEBUG: invalid response type {data}"); raise ValueError("LLM returned an invalid response type")
    if 'error' in data and data['error'] is not None:
        raise LLMProviderError(data['error'])
    choices = data.get("choices") or []
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        print(f"DEBUG: no choices {data}"); raise ValueError("LLM returned no choices")
    if 'error' in choices[0] and choices[0]['error'] is not None:
        raise LLMProviderError(choices[0]['error'])
    if choices[0].get('finish_reason') not in (None, 'stop', 'eos', 'end_turn', 'length'):
        raise ValueError(f"LLM response was truncated or invalid: {choices[0].get('finish_reason')}")
    message = choices[0].get('message')
    if not isinstance(message, dict) or message.get('refusal') or message.get('tool_calls'):
        print(f"DEBUG: refusal {data}"); raise ValueError('LLM returned a refusal or unsupported tool request')
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        print(f"DEBUG: no text content {data}"); raise ValueError("LLM returned no text content")
    return unfence(content)
