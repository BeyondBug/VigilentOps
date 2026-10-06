"""Dynamic Multi-Model Fallback Pool reading from .env"""

import hashlib
import time

OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions'

def bounded_integer(environment, name, default, minimum, maximum):
    try:
        value = int(environment.get(name, default))
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be an integer') from None
    if not minimum <= value <= maximum:
        raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return value

def load_model_pool(environment):
    """Load up to 9 models defined in the .env file as MODEL_1, API_KEY_1, API_URL_1"""
    models = []
    
    for i in range(1, 10):
        model = environment.get(f'MODEL_{i}', '').strip()
        key = environment.get(f'API_KEY_{i}', '').strip()
        url = environment.get(f'API_URL_{i}', '').strip()
        
        # Also support the hardcoded OpenRouter key as a fallback if present
        if not key and url and 'openrouter' in url:
            key = environment.get('OPENROUTER_API_KEY', '').strip()
            
        if model and key and url:
            models.append({'model': model, 'key': key, 'url': url})
            
    if not models:
        # Emergency fallback if .env isn't loaded correctly
        key = environment.get('OPENROUTER_API_KEY', '').strip()
        if key:
            return [{'model': 'google/gemma-4-31b-it:free', 'key': key, 'url': OPENROUTER_URL}]
        raise ValueError('No models configured in .env and no OPENROUTER_API_KEY found!')
        
    return models

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
