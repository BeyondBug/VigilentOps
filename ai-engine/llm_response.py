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
    if not choices:
        raise ValueError("LLM returned no choices")
    content = choices[0].get("message", {}).get("content")
    if not content:
        raise ValueError("LLM returned no text content")
    return unfence(content)
