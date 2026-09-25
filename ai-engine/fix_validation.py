"""Syntax and content checks for generated file replacements."""

import ast
import json as _json
import logging
import re

log = logging.getLogger("ai-fix-v3")


def parses_ok(path: str, content: str) -> bool:
    if path.endswith(".py"):
        try:
            ast.parse(content); return True
        except SyntaxError as e:
            log.warning(f"REJECT {path}: syntax error L{e.lineno}: {e.msg}")
            return False
    if path.endswith(".json"):
        try:
            _json.loads(content); return True
        except Exception:
            log.warning(f"REJECT {path}: invalid JSON"); return False
    if path.endswith(".txt"):
        bad = [l for l in content.splitlines()
               if l.strip() and not re.match(r'^[A-Za-z0-9._\-\[\]]+\s*[=<>!~]', l.strip())]
        if bad:
            log.warning(f"REJECT {path}: {len(bad)} malformed requirement lines")
            return False
    return True

