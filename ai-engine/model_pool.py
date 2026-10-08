"""Explicit model routes and bounded, process-local cooldowns. No API discovery."""

import hashlib
import time
from urllib.parse import urlsplit

MAX_ROUTES = 32
OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions'

# User-approved free variants; catalog presence is not remediation acceptance.
OPENROUTER_FREE_MODELS = (
    'google/gemma-4-31b-it:free',
    'nvidia/nemotron-3-super-120b-a12b:free',
    'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free',
    'thinkingmachines/inkling:free',
    'liquid/lfm-2.5-2.6b:free',
    'poolside/laguna-s-2.1:free',
    'nvidia/nemotron-3-ultra-550b-a55b:free',
    'cohere/north-mini-code:free',
    'openrouter/free'
)

def bounded_integer(environment, name, default, minimum, maximum):
    try:
        value = int(environment.get(name, default))
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be an integer') from None
    if not minimum <= value <= maximum:
        raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return value

OLLAMA_URL = 'http://172.18.0.1:11434/v1/chat/completions'
OLLAMA_PRIMARY_MODEL = 'deepseek-coder:6.7b'
OLLAMA_FALLBACK_MODEL = 'qwen2.5-coder:7b'

def load_model_pool(environment):
    """Local inference is opt-in; legacy cloud configuration stays supported."""
    key = environment.get('OPENROUTER_API_KEY', '').strip()
    if key == 'your_openrouter_api_key':
        key = ''
    mode = environment.get('AI_MODE', 'openrouter' if key else 'off').strip().lower()
    if mode not in {'off', 'openrouter', 'local', 'hybrid'}:
        raise ValueError('AI_MODE must be off, openrouter, local or hybrid')
    routes = []
    if mode in {'local', 'hybrid'}:
        url = environment.get('OLLAMA_URL', OLLAMA_URL).strip()
        parsed = urlsplit(url)
        if (parsed.scheme not in {'http', 'https'} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path != '/v1/chat/completions'):
            raise ValueError('OLLAMA_URL must be an HTTP(S) chat-completions endpoint without credentials')
        primary = environment.get('OLLAMA_MODEL', OLLAMA_PRIMARY_MODEL).strip()
        fallback = environment.get('OLLAMA_FALLBACK_MODEL', OLLAMA_FALLBACK_MODEL).strip()
        for model in dict.fromkeys([primary, fallback]):
            if model:
                routes.append({'model': model, 'key': 'ollama', 'url': url})
        if not routes:
            raise ValueError('Local AI mode requires a model')
    if mode in {'openrouter', 'hybrid'} and key:
        models = environment.get('OPENROUTER_MODELS', ','.join(OPENROUTER_FREE_MODELS))
        selected = list(dict.fromkeys(model.strip() for model in models.split(',') if model.strip()))
        if any(model not in OPENROUTER_FREE_MODELS for model in selected):
            raise ValueError('OPENROUTER_MODELS contains an unapproved free model')
        routes.extend({'model': model, 'key': key, 'url': OPENROUTER_URL} for model in selected)
    return routes

def completion_options(model, api_url):
    if api_url == OPENROUTER_URL:
        if model not in OPENROUTER_FREE_MODELS:
            raise ValueError('Only approved free OpenRouter models are permitted')
        return {'provider': {'max_price': {'prompt': 0, 'completion': 0, 'request': 0}}}
    return {}

def route_identity(route):
    return hashlib.sha256((route['url'] + '\0' + route['model'] + '\0' + route['key']).encode()).hexdigest()

class RouteCooldowns:
    def __init__(self):
        self.deadlines = {}

    def remaining(self, route):
        identity = route_identity(route)
        deadline = self.deadlines.get(identity, 0)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            self.deadlines.pop(identity, None)
            return 0
        return max(1, int(remaining + 0.999))

    def defer(self, route, seconds):
        identity = route_identity(route)
        deadline = time.monotonic() + max(1, min(3600, seconds))
        self.deadlines[identity] = max(deadline, self.deadlines.get(identity, 0))

    def clear(self, route):
        self.deadlines.pop(route_identity(route), None)
