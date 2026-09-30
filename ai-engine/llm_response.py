import re


FENCE_RE = re.compile(
    r"^\s*```[a-zA-Z0-9_+.\-]*\s*\n(.*?)\n\s*```\s*$",
    re.DOTALL,
)


def unfence(text: str) -> str:
    match = FENCE_RE.match(text.strip())
    return match.group(1) if match else text.strip()


def extract_llm_content(data) -> str:
    """Extract text from object or one-element-array chat responses."""
    if isinstance(data, list):
        if not data:
            raise ValueError("LLM returned an empty response")
        data = data[0]
    if not isinstance(data, dict):
        raise ValueError("LLM returned an invalid response type")
    choices = data.get("choices") or []
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError("LLM returned no choices")
    if choices[0].get('finish_reason') not in (None, 'stop'):
        raise ValueError('LLM response was truncated, filtered or requires tool execution')
    message = choices[0].get('message')
    if not isinstance(message, dict) or message.get('refusal') or message.get('tool_calls'):
        raise ValueError('LLM returned a refusal or unsupported tool request')
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("LLM returned no text content")
    return unfence(content)
