"""Explicit model routes and bounded, process-local cooldowns. No API discovery."""

import hashlib
import re
import time
from urllib.parse import urlsplit


MAX_ROUTES = 32


def bounded_integer(environment, name, default, minimum, maximum):
    try:
        value = int(environment.get(name, default))
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be an integer') from None
    if not minimum <= value <= maximum:
        raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return value


def load_model_pool(environment):
    """Numbered routes first, explicit NVIDIA allowlist second, legacy last."""
    routes = []
    indices = sorted({int(match.group(1)) for key in environment
                      if (match := re.fullmatch(r'MODEL_([1-9][0-9]*)', key))})
    for index in indices:
        model = environment.get(f'MODEL_{index}', '').strip()
        key = environment.get(f'API_KEY_{index}', '').strip()
        url = environment.get(f'API_URL_{index}', '').strip()
        if model and key and url:
            routes.append({'model': model, 'key': key, 'url': url})
    nim_models = environment.get('NVIDIA_NIM_MODELS', '').strip()
    nim_key = environment.get('NVIDIA_NIM_API_KEY', '').strip()
    if nim_models and nim_key:
        for model in nim_models.split(','):
            if model.strip():
                routes.append({'model': model.strip(), 'key': nim_key,
                               'url': 'https://integrate.api.nvidia.com/v1/chat/completions'})
    if not routes:
        for prefix, model, url in (
            ('PRIMARY', 'moonshotai/kimi-k3', 'https://api.moonshot.cn/v1/chat/completions'),
            ('SECONDARY', 'deepseek-ai/deepseek-v4-flash-0731', 'https://api.deepseek.com/chat/completions'),
            ('FALLBACK', 'meta/muse-glimmer-30b', 'https://api.together.xyz/v1/chat/completions'),
        ):
            key = environment.get(f'{prefix}_API_KEY', '').strip()
            if key:
                routes.append({'model': environment.get(f'{prefix}_MODEL', model).strip(),
                               'key': key, 'url': environment.get(f'{prefix}_API_URL', url).strip()})
    unique = {}
    for route in routes:
        parsed = urlsplit(route['url'])
        if (parsed.scheme not in {'https', 'http'} or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment
                or not parsed.path.endswith('/chat/completions')):
            raise ValueError('Model endpoint must be a chat-completions URL without embedded credentials/query/fragment')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_.:-]{0,199}', route['model']):
            raise ValueError('Model identifier contains unsupported characters')
        unique.setdefault(route_identity(route), route)
    if len(unique) > MAX_ROUTES:
        raise ValueError(f'Configure at most {MAX_ROUTES} distinct model routes')
    return list(unique.values())


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
