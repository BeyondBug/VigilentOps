"""Normalize scanner reports into finding records."""

import re
from urllib.parse import unquote


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
SUPPORTED_TOOLS = {'semgrep', 'bandit', 'gitleaks', 'trivy', 'trivy-deps', 'trivy-image',
                   'grype', 'osv', 'dep-check', 'checkov', 'snyk', 'dockle', 'syft-sbom', 'hadolint', 'shellcheck'}
REQUIRED_TOOLS = {'semgrep', 'gitleaks', 'trivy-deps', 'grype', 'osv', 'dep-check', 'syft-sbom', 'hadolint', 'shellcheck'}


def validate_report_shape(data, tool: str) -> None:
    """Reject uploads that would otherwise be acknowledged without parsing."""
    if tool not in SUPPORTED_TOOLS:
        raise ValueError('Unsupported scanner tool')
    if not isinstance(data, dict):
        raise ValueError("report must be a JSON object")
    if tool == "bandit":
        if not isinstance(data.get("results"), list) or any(not isinstance(item, dict) for item in data['results']):
            raise ValueError("Bandit report needs a results list")
        if data.get('errors'):
            raise ValueError('Bandit could not analyze every selected file')
        return
    elif tool == "syft-sbom":
        if not str(data.get("spdxVersion", "")).startswith("SPDX-") or not isinstance(data.get('packages'), list):
            raise ValueError("Syft report needs an SPDX version")
        return
    elif data.get("version") != "2.1.0" or not isinstance(data.get("runs"), list) or not data["runs"]:
        raise ValueError("scanner report must be SARIF 2.1.0")
    elif any(
        not isinstance(run, dict) or
        not isinstance(run.get("results"), list) or
        any(not isinstance(result, dict) for result in run["results"])
        for run in data["runs"]
    ):
        raise ValueError("SARIF runs and results must be valid lists")
    for run in data.get('runs', []):
        invocations = run.get('invocations', [])
        if not isinstance(invocations, list) or any(not isinstance(item, dict) or item.get('executionSuccessful') is False for item in invocations):
            raise ValueError('Scanner invocation failed or is malformed')
        properties = run.get('properties', {})
        if not isinstance(properties, dict):
            raise ValueError('SARIF run properties must be an object')
        if properties.get('coverage') == 'not_applicable':
            expected_exit = 128 if tool == 'osv' else 0
            if (tool not in {'osv', 'hadolint', 'shellcheck'} or run['results']
                    or not any(item.get('exitCode') == expected_exit and item.get('executionSuccessful') is True for item in invocations)
                    or (tool != 'osv' and properties.get('scanned_file_count') != 0)):
                raise ValueError('Not-applicable coverage requires an explicit supported scanner result')

def _extract_cve(rule_id: str, rule: dict, result: dict):
    direct = CVE_RE.search(rule_id)
    if direct:
        return direct.group(0)
    blob = " ".join([
        rule.get("fullDescription", {}).get("text", ""),
        rule.get("shortDescription", {}).get("text", ""),
        result.get("message", {}).get("text", ""),
    ])
    m = CVE_RE.search(blob)
    if m:
        return m.group(0)
    return rule_id if rule_id.startswith("GHSA-") else None


def _score(value):
    try:
        score = float(value)
        return score if 0 <= score <= 10 else None
    except (TypeError, ValueError):
        return None


def _label(text, name):
    match = re.search(r'^' + re.escape(name) + r':[ \t]*([^\r\n]*)', text, re.MULTILINE)
    return match.group(1).strip() if match else None


def _metadata(rule, result, run):
    properties = {**rule.get('properties', {}), **result.get('properties', {})}
    message = result.get('message', {}).get('text', '')
    help_text = rule.get('help', {}).get('text', '')
    text = message + '\n' + help_text
    score = _score(properties.get('cvss_score', properties.get('security-severity')))
    severity = str(properties.get('severity') or _label(text, 'Severity') or '').upper()
    if severity not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'}:
        severity = ('CRITICAL' if score >= 9 else 'HIGH' if score >= 7 else 'MEDIUM' if score >= 4 else 'LOW') if score is not None else None
    package = properties.get('package') or properties.get('packageName') or _label(text, 'Package')
    installed = properties.get('installed_version') or properties.get('installedVersion') or _label(text, 'Installed Version') or _label(text, 'Version')
    fixed = properties.get('fixed_version') or properties.get('fixedVersion') or _label(text, 'Fixed Version') or _label(text, 'Fix Version')
    return {
        'severity': severity or {'error': 'HIGH', 'warning': 'MEDIUM', 'note': 'LOW', 'none': 'INFO'}.get(result.get('level', 'warning'), 'MEDIUM'),
        'cvss_score': score,
        'package': str(package)[:500] if package else None,
        'installed_version': str(installed)[:500] if installed else None,
        'fixed_version': str(fixed)[:500] if fixed else None,
        'image': str(run.get('properties', {}).get('imageName') or properties.get('image') or '')[:1000] or None,
    }

def parse_sarif(sarif_data: dict, tool: str) -> list[dict]:
    """Parse SARIF 2.1.0 format into finding dicts."""
    findings = []
    for run in sarif_data.get("runs", []):
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            locs   = result.get("locations", [{}])
            loc    = locs[0].get("physicalLocation", {}) if locs else {}
            region = loc.get("region", {})
            rule_id = result.get("ruleId", "")
            rule    = rules.get(rule_id, {})
            metadata = _metadata(rule, result, run)
            finding_class = determine_finding_class(tool)
            if tool.startswith('trivy') and rule.get('name') == 'Secret':
                finding_class = 'secret'

            findings.append({
                "scanner":        tool,
                "rule_id":        rule_id,
                "cve_id":         None if finding_class == 'quality' else (result.get("properties", {}).get("cve_id")
                                   or _extract_cve(rule_id, rule, result)),
                "cwe_id":         result.get("properties", {}).get("cwe_id"),
                **metadata,
                "title":          (rule.get("shortDescription", {}).get("text") or rule.get("name") or
                                   result.get("message", {}).get("text", rule_id) or
                                   rule_id)[:500],
                "description":    ('\n'.join(filter(None, [result.get("message", {}).get("text", ""),
                                   rule.get("fullDescription", {}).get("text", "")]))[:2000],
                "file_path":      (unquote(loc.get("artifactLocation", {}).get("uri", ""))
                                   if finding_class == 'quality' else loc.get("artifactLocation", {}).get("uri", "")),
                "line_start":     region.get("startLine"),
                "line_end":       region.get("endLine"),
                "vulnerable_code": result.get("properties", {}).get("snippet", "")[:5000],
                "finding_class": finding_class,
            })
    return findings



def determine_finding_class(tool: str) -> str:
    t = tool.lower()
    if t in {'hadolint', 'shellcheck'}: return 'quality'
    if t in ["trivy", "trivy-deps", "trivy-image", "grype", "syft", "syft-sbom",
             "osv", "osv-scanner", "dependency-check", "dep-check", "snyk"]: return "sca"
    if t in ["semgrep", "bandit", "sonarqube", "zap"]: return "sast"
    if t in ["gitleaks", "trufflehog"]: return "secret"
    if t in ["checkov", "terrascan", "openscap", "dockle"]: return "iac"
    return "sast"

def parse_bandit(bandit_data: dict) -> list[dict]:
    """Parse Bandit JSON format into finding dicts."""
    findings = []
    sev_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    for issue in bandit_data.get("results", []):
        findings.append({
            "scanner":        "bandit",
            "rule_id":        issue.get("test_id", ""),
            "cve_id":         None,
            "cwe_id":         str(issue.get("issue_cwe", {}).get("id", "")),
            "severity":       sev_map.get(issue.get("issue_severity", "MEDIUM"), "MEDIUM"),
            "cvss_score":     None,
            "title":          issue.get("test_name", "")[:500],
            "description":    issue.get("issue_text", "")[:2000],
            "file_path":      issue.get("filename", "").removeprefix("/src/"),
            "line_start":     issue.get("line_number"),
            "line_end":       (issue.get("line_range") or [None])[-1],
            "vulnerable_code": issue.get("code", "")[:5000],
            "finding_class": determine_finding_class("bandit"),
        })
    return findings
