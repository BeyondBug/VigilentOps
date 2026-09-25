"""Normalize scanner reports into finding records."""

import re


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

def _extract_cve(rule_id: str, rule: dict, result: dict):
    if rule_id.startswith("CVE-"):
        return rule_id
    blob = " ".join([
        rule.get("fullDescription", {}).get("text", ""),
        rule.get("shortDescription", {}).get("text", ""),
        result.get("message", {}).get("text", ""),
    ])
    m = CVE_RE.search(blob)
    if m:
        return m.group(0)
    return rule_id if rule_id.startswith("GHSA-") else None

def parse_sarif(sarif_data: dict, tool: str) -> list[dict]:
    """Parse SARIF 2.1.0 format into finding dicts."""
    findings = []
    for run in sarif_data.get("runs", []):
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for result in run.get("results", []):
            sev_map = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
            level   = result.get("level", "warning")
            sev     = result.get("properties", {}).get("severity",
                        sev_map.get(level, "MEDIUM")).upper()

            locs   = result.get("locations", [{}])
            loc    = locs[0].get("physicalLocation", {}) if locs else {}
            region = loc.get("region", {})
            rule_id = result.get("ruleId", "")
            rule    = rules.get(rule_id, {})

            findings.append({
                "scanner":        tool,
                "rule_id":        rule_id,
                "cve_id":         (result.get("properties", {}).get("cve_id")
                                   or _extract_cve(rule_id, rule, result)),
                "cwe_id":         result.get("properties", {}).get("cwe_id"),
                "severity":       sev,
                "cvss_score":     result.get("properties", {}).get("cvss_score"),
                "title":          (rule.get("name") or
                                   result.get("message", {}).get("text", rule_id) or
                                   rule_id)[:500],
                "description":    (rule.get("fullDescription", {}).get("text") or
                                   result.get("message", {}).get("text", ""))[:2000],
                "file_path":      loc.get("artifactLocation", {}).get("uri", ""),
                "line_start":     region.get("startLine"),
                "line_end":       region.get("endLine"),
                "vulnerable_code": result.get("properties", {}).get("snippet", "")[:5000],
                "finding_class": determine_finding_class(tool),
            })
    return findings



def determine_finding_class(tool: str) -> str:
    t = tool.lower()
    if t in ["trivy", "trivy-deps", "trivy-image", "grype", "syft", "syft-sbom",
             "osv", "osv-scanner", "dependency-check", "dep-check", "snyk"]: return "sca"
    if t in ["semgrep", "bandit", "sonarqube", "zap"]: return "sast"
    if t in ["gitleaks", "trufflehog"]: return "secret"
    if t in ["checkov", "terrascan", "openscap"]: return "iac"
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


