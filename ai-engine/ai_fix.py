import os
import json
import httpx

# NVIDIA NIM — OpenAI-compatible endpoint, free tier available
# Models: https://build.nvidia.com/models
NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_MODEL   = os.getenv("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct")

class AIFixEngine:
    def __init__(self):
        if not NVIDIA_API_KEY:
            print("[AIFixEngine] WARNING: NVIDIA_API_KEY not set — AI fixes disabled")
        self.headers = {
            "Authorization": f"Bearer {NVIDIA_API_KEY}",
            "Content-Type": "application/json",
        }

    def generate_fix(self, finding: dict, repo_path: str) -> dict:
        if not NVIDIA_API_KEY:
            return {
                "fixed_code": "",
                "explanation": "NVIDIA_API_KEY not configured",
                "confidence": 0.0
            }

        file_path    = finding.get("file", "")
        code_snippet = finding.get("code_snippet", "")

        # Read surrounding context from the actual file (±15 lines)
        full_context = code_snippet
        try:
            abs_path = os.path.join(repo_path, file_path)
            if os.path.exists(abs_path):
                with open(abs_path, "r", errors="ignore") as f:
                    lines = f.readlines()
                line_no = max(0, finding.get("line", 1) - 1)
                start   = max(0, line_no - 15)
                end     = min(len(lines), line_no + 15)
                full_context = "".join(lines[start:end])
        except Exception:
            pass

        system_prompt = (
            "You are a secure code reviewer and expert programmer. "
            "When given vulnerable code, you rewrite ONLY the affected "
            "function or statement to eliminate the vulnerability while "
            "preserving all original functionality. "
            "Always respond with ONLY a valid JSON object — no markdown, "
            "no explanation outside the JSON."
        )

        user_prompt = f"""The following code has a security vulnerability:
- Rule/CVE : {finding.get('rule_id', 'unknown')} / {finding.get('cve_id', 'N/A')}
- CWE      : {finding.get('cwe', 'unknown')}
- Severity : {finding.get('severity', 'HIGH')} (CVSS: {finding.get('cvss_score', 'N/A')})
- Issue    : {finding.get('message', '')}

VULNERABLE CODE (file: {file_path}, around line {finding.get('line', 0)}):
{full_context}

Respond with ONLY this JSON (no markdown, no backticks):
{{
  "fixed_code": "the corrected code here",
  "explanation": "one sentence — what changed and why",
  "confidence": 0.85
}}"""

        try:
            with httpx.Client(timeout=40) as client:
                response = client.post(
                    NVIDIA_API_URL,
                    headers=self.headers,
                    json={
                        "model": NVIDIA_MODEL,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user",   "content": user_prompt}
                        ],
                        "max_tokens": 1024,
                        "temperature": 0.1,   # low temp = more deterministic fixes
                        "top_p": 0.9,
                    }
                )
                response.raise_for_status()
                data = response.json()
                text = data["choices"][0]["message"]["content"].strip()

                # Strip accidental markdown fences
                if text.startswith("```"):
                    parts = text.split("```")
                    text = parts[1] if len(parts) > 1 else text
                    if text.startswith("json"):
                        text = text[4:]
                text = text.strip()

                return json.loads(text)

        except json.JSONDecodeError as e:
            print(f"[AIFixEngine] JSON parse error: {e}")
            return {"fixed_code": "", "explanation": f"Parse error: {e}", "confidence": 0.0}
        except httpx.HTTPStatusError as e:
            print(f"[AIFixEngine] NVIDIA API HTTP error: {e.response.status_code} — {e.response.text[:200]}")
            return {"fixed_code": "", "explanation": str(e), "confidence": 0.0}
        except Exception as e:
            print(f"[AIFixEngine] Error: {e}")
            return {"fixed_code": "", "explanation": str(e), "confidence": 0.0}
