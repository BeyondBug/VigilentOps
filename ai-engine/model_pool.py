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


def load_model_pool(environment):
    """Only the seven approved OpenRouter free models; no other provider fallback."""
    configured = ','.join(OPENROUTER_FREE_MODELS)  # FORCED
    models = list(dict.fromkeys(model.strip() for model in configured.split(',') if model.strip()))
    if any(model not in OPENROUTER_FREE_MODELS for model in models):
        raise ValueError('OPENROUTER_MODELS must contain only approved free model IDs')
    key = environment.get('OPENROUTER_API_KEY', '').strip()
    if not key:
        return []
    return [{'model': model, 'key': key, 'url': OPENROUTER_URL} for model in models]


def completion_options(model, api_url):
    """Price constraints for production routes; local transport fixtures remain generic."""
    if api_url != OPENROUTER_URL:
        return {}
    if model not in OPENROUTER_FREE_MODELS:
        raise ValueError('OpenRouter model is outside the approved free allowlist')
    return {'provider': {'max_price': {'prompt': 0, 'completion': 0, 'request': 0}}}


def route_identity(route):
    return hashlib.sha256((route['url'] + '\0' + route['model'] + '\0' + route['key']).encode()).hexdigest()


class RouteCooldowns:
    """One worker process; state expires naturally and resets on restart."""

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
