"""Syntax and content checks for generated file replacements."""

import ast
import json as _json
import logging
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

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


def _bandit_results(content: str) -> list[dict]:
    # Bandit parses source; it does not import or execute the target file.
    with tempfile.TemporaryDirectory(prefix="sg_bandit_") as directory:
        source = Path(directory) / "candidate.py"
        source.write_text(content, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "--ignore-nosec", "-q", "-f", "json", str(source)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode not in (0, 1):
            raise ValueError("Bandit could not validate the candidate")
        report = _json.loads(result.stdout)
        if report.get("errors") or not isinstance(report.get("results"), list):
            raise ValueError("Bandit returned an incomplete candidate report")
        return report["results"]


def validates_security_change(original: str, proposed: str, findings: list[dict]) -> tuple[bool, str]:
    """Reject ineffective Bandit fixes and newly introduced medium/high rules."""
    contract_reason = _unsafe_contract_change(original, proposed)
    if contract_reason:
        return False, contract_reason
    target_rules = {str(item.get("rule_id") or "") for item in findings
                    if str(item.get("scanner") or "").lower() == "bandit"}
    target_rules = {rule for rule in target_rules if re.fullmatch(r"B\d{3}", rule)}
    if not target_rules:
        return True, "Non-Bandit findings still require a reviewer and server rescan"
    try:
        before = _bandit_results(original)
        after = _bandit_results(proposed)
    except (ValueError, OSError, subprocess.TimeoutExpired, _json.JSONDecodeError):
        return False, "Bandit validation unavailable; keep the finding open"
    observed = {issue["test_id"] for issue in before}
    if not target_rules <= observed:
        return False, "Original Bandit rules were not reproduced; review scan context manually"
    remaining = target_rules & {issue["test_id"] for issue in after}
    if remaining:
        return False, "Bandit still reports " + ", ".join(sorted(remaining))
    def significant(issues):
        return Counter((issue["test_id"], issue["issue_severity"]) for issue in issues
                       if issue["issue_severity"] in {"MEDIUM", "HIGH"})
    if significant(after) - significant(before):
        return False, "Candidate introduces additional medium/high Bandit findings"
    return True, "Targeted Bandit rules absent; runtime behavior remains unverified"


def _unsafe_contract_change(original: str, proposed: str) -> str | None:
    """Conservative checks for two observed unsafe model substitutions.

    These are review gates, not a general proof of behavior or cryptography.
    Input-format and password-hash migrations need client/data review.
    """
    def functions(content):
        tree = ast.parse(content)
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name] = item.name
            elif isinstance(node, ast.ImportFrom):
                for item in node.names:
                    aliases[item.asname or item.name] = f'{node.module}.{item.name}'
        def name(node):
            if isinstance(node, ast.Name):
                return aliases.get(node.id, node.id)
            if isinstance(node, ast.Attribute):
                return name(node.value) + '.' + node.attr
            return ''
        found = {}
        def collect(nodes, prefix=''):
            for node in nodes:
                if isinstance(node, ast.ClassDef):
                    collect(node.body, prefix + node.name + '.')
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    calls = {name(item.func) for item in ast.walk(node) if isinstance(item, ast.Call)}
                    parameters = {item.arg.lower() for item in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]}
                    found[prefix + node.name] = (calls, parameters)
                else:
                    collect(list(ast.iter_child_nodes(node)), prefix)
        collect(tree.body)
        return found
    try:
        before, after = functions(original), functions(proposed)
    except SyntaxError:
        return 'Candidate syntax unavailable for contract review'
    for function, (calls, parameters) in before.items():
        replacement = after.get(function, (set(), set()))[0]
        if calls & {'pickle.load', 'pickle.loads'} and not replacement & {'pickle.load', 'pickle.loads'}:
            if replacement & {'json.load', 'json.loads'}:
                return 'Pickle-to-JSON input migration requires explicit client/data review'
        password_input = parameters & {'pw', 'password', 'passwd', 'passphrase'}
        if password_input and calls & {'hashlib.md5', 'hashlib.sha1'}:
            if replacement & {'hashlib.sha224', 'hashlib.sha256', 'hashlib.sha384', 'hashlib.sha512'}:
                return 'Fast digest is not a password KDF; hash migration requires explicit review'
    return None


def preserves_python_interface(original: str, proposed: str) -> bool:
    def signatures(content):
        found = {}
        def structure(node):
            return ast.dump(node, include_attributes=False) if node is not None else None
        def collect(nodes, prefix=""):
            for node in nodes:
                if isinstance(node, ast.ClassDef):
                    found.setdefault(prefix + node.name, []).append((
                        "class", tuple(structure(base) for base in node.bases),
                        tuple(structure(keyword) for keyword in node.keywords),
                        tuple(structure(decorator) for decorator in node.decorator_list),
                    ))
                    collect(node.body, prefix + node.name + ".")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    arguments = node.args
                    found.setdefault(prefix + node.name, []).append((
                        type(node).__name__, tuple(arg.arg for arg in arguments.posonlyargs),
                        tuple(arg.arg for arg in arguments.args),
                        tuple(arg.arg for arg in arguments.kwonlyargs),
                        arguments.vararg.arg if arguments.vararg else None,
                        arguments.kwarg.arg if arguments.kwarg else None,
                        # Default values may need a security fix; optionality must remain.
                        len(arguments.defaults), tuple(value is not None for value in arguments.kw_defaults),
                        tuple(structure(arg.annotation) for arg in
                              [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]),
                        structure(arguments.vararg.annotation) if arguments.vararg else None,
                        structure(arguments.kwarg.annotation) if arguments.kwarg else None,
                        structure(node.returns),
                        tuple(structure(decorator) for decorator in node.decorator_list),
                    ))
                else:
                    # Public definitions may be inside module/class conditionals.
                    # Function bodies are deliberately excluded above.
                    collect(list(ast.iter_child_nodes(node)), prefix)
        collect(ast.parse(content).body)
        return found
    try:
        before, after = signatures(original), signatures(proposed)
        return all(after.get(name) == signature for name, signature in before.items())
    except SyntaxError:
        return False
