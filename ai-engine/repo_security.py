"""Trusted Gitea clone coordinates, independent of model configuration."""

import os
import re
from urllib.parse import urlparse


def canonical_repo_url(repo_url: str) -> str:
    parsed = urlparse(repo_url)
    allowed_hosts = {
        h.strip() for h in os.getenv(
            "GITEA_ALLOWED_HOSTS", "sg-gitea,gitea,localhost"
        ).split(",") if h.strip()
    }
    try:
        valid_port = parsed.port == 3000
    except ValueError:
        valid_port = False
    parts = parsed.path.strip('/').removesuffix('.git').split('/')
    if (parsed.scheme not in ('http', 'https') or parsed.hostname not in allowed_hosts
            or not valid_port or parsed.username or parsed.password or parsed.query or parsed.fragment
            or len(parts) != 2 or any(part in {'.', '..'} for part in parts)
            or not re.fullmatch(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git', parsed.path)):
        raise ValueError('Repository URL is outside the configured Gitea clone origin/path')
    # All Git traffic stays within the canonical private Docker Gitea service.
    return 'http://sg-gitea:3000' + parsed.path

