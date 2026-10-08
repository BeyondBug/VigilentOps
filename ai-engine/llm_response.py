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
    cleaned = text.strip()
    match = FENCE_RE.match(cleaned)
    if match:
        return match.group(1).strip()
    # If the model included conversational text before/after the fence:
    embedded_match = re.search(r"```[a-zA-Z0-9_+.\-]*\s*\n(.*?)\n\s*```", cleaned, re.DOTALL)
    if embedded_match:
        return embedded_match.group(1).strip()
    return cleaned


def extract_llm_content(data) -> str:
    """Extract text from object or one-element-array chat responses."""
    if isinstance(data, list):
        if not data:
            raise ValueError("LLM returned an empty response")
        data = data[0]
    if not isinstance(data, dict):
        raise ValueError("LLM returned an invalid response type")
    if 'error' in data and data['error'] is not None:
        raise LLMProviderError(data['error'])
    choices = data.get("choices") or []
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError("LLM returned no choices")
    if 'error' in choices[0] and choices[0]['error'] is not None:
        raise LLMProviderError(choices[0]['error'])
    if choices[0].get('finish_reason') not in (None, 'stop', 'eos', 'end_turn'):
        raise ValueError("LLM response was truncated or invalid")
    message = choices[0].get('message')
    if not isinstance(message, dict) or message.get('refusal') or message.get('tool_calls'):
        raise ValueError('LLM returned a refusal or unsupported tool request')
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("LLM returned no text content")
    return unfence(content)
