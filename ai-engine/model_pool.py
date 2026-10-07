"""Explicit model routes and bounded, process-local cooldowns. No API discovery."""

import hashlib
import time

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
OLLAMA_MODEL = 'qwen2.5-coder:7b'

def load_model_pool(environment):
    """Prioritize local Ollama model (no rate limits or token cuts)."""
    ollama_url = environment.get('OLLAMA_URL', OLLAMA_URL)
    ollama_model = environment.get('OLLAMA_MODEL', OLLAMA_MODEL)
    
    routes = [{
        'model': ollama_model,
        'key': 'ollama',
        'url': ollama_url
    }]

    key = environment.get('OPENROUTER_API_KEY', '').strip()
    if key and key != 'your_openrouter_api_key':
        routes.append({'model': 'qwen/qwen-2.5-coder-32b-instruct:free', 'key': key, 'url': OPENROUTER_URL})
    return routes

def completion_options(model, api_url):
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
