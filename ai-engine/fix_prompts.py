"""Prompts used by the remediation model chain."""


def build_primary_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\n"
    return f"""You are the Primary AI Fix Engine (Moonshot Kimi). Fix ALL vulnerabilities strictly.
FILE: {file_path}
VULNERABILITIES TO FIX:
{vuln_list}
CURRENT FILE CONTENT:
```
{file_content}
```
OUTPUT RULES:
- You MUST wrap your final fixed code in a single markdown block (```)
- The markdown block must contain the FULL file content, not just a snippet."""

def build_secondary_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\n"
    return f"""You are the Secondary AI Fix Engine (DeepSeek V4).
FILE: {file_path}
VULNS:
{vuln_list}
CODE:
```
{file_content}
```
Rule: Return the FULL fixed code wrapped in a markdown block (```)."""

def build_fallback_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\n"
    return f"""You are the Fallback Fix Engine (Muse Glimmer).
Fix this code.
FILE: {file_path}
VULNS:
{vuln_list}
CODE:
```
{file_content}
```
Return the code wrapped in ```"""

def build_fix_prompt(file_path: str, file_content: str,
                      findings: list[dict]) -> str:
    """
    Build a prompt that lists ALL vulnerabilities in a file
    and asks NIM to return the COMPLETE fixed file.
    """
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += (
            f"\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: "
            f"[{f.get('severity')}] {f.get('title','')}\n"
            f"   Rule: {f.get('rule_id') or f.get('cve_id') or 'N/A'} | "
            f"CWE: {f.get('cwe_id') or 'N/A'}\n"
            f"   Detail: {str(f.get('description',''))[:150]}\n"
        )

    return f"""You are a code security tool. Fix ALL vulnerabilities listed below in the file.

FILE: {file_path}
VULNERABILITIES TO FIX:
{vuln_list}

CURRENT FILE CONTENT:
```
{file_content}
```

STRICT RULES:
1. Fix EVERY vulnerability listed above
2. Return ONLY the complete fixed file content — nothing else
3. NO comments explaining what you changed
4. NO markdown code fences (no ``` or ```python)
5. NO preamble, NO explanation, NO notes after the code
6. Preserve all existing functionality — only change security-relevant lines
7. Use parameterized queries for SQL injection
8. Use subprocess with shell=False and list args for command injection
9. Replace weak crypto (md5/sha1) with bcrypt or hashlib.sha256
10. Replace pickle with json for deserialization
11. Replace hardcoded secrets with os.environ.get()
12. For requirements.txt: bump vulnerable packages to latest safe versions

OUTPUT RULES (violating any = failure):
- Output ONLY raw source code — zero other text
- Do NOT open with any explanation, preamble, or thinking steps
- Do NOT close with any explanation or notes
- Do NOT wrap in markdown fences (no ``` or ```python)
- First line of output = first line of the fixed file
- Last line of output = last line of the fixed file"""



def build_sca_prompt(file_path: str, file_content: str,
                      findings: list[dict]) -> str:
    """Prompt specifically for requirements.txt version bumps."""
    cve_list = ""
    seen = set()
    for f in findings:
        cve = f.get("cve_id", "unknown")
        title = f.get("title", "")
        desc  = f.get("description", "")[:120]
        key   = f"{cve}:{f.get('line_start')}"
        if key not in seen:
            seen.add(key)
            cve_list += f"  - Line {f.get('line_start')}: {cve} — {desc}\n"

    return f"""You are a Python security expert. Update package versions in requirements.txt to fix CVEs.

FILE: {file_path}
CURRENT CONTENT:
{file_content}

CVEs TO FIX:
{cve_list}

RULES:
1. Return ONLY the complete fixed requirements.txt content
2. Bump each vulnerable package to the minimum safe version that fixes its CVE
3. Keep all other packages unchanged
4. No comments, no explanation, no markdown
5. First line of output must be the first line of requirements.txt"""


