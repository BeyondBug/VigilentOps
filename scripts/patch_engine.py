import re
with open("ai-engine/fix_engine.py", "r") as f:
    code = f.read()

# Replace config
old_config = """# ── Config ────────────────────────────────────────────────────
NVIDIA_API_URL   = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_API_KEY   = os.getenv("NVIDIA_API_KEY", "")
PRIMARY_MODEL    = os.getenv("NVIDIA_MODEL",   "nvidia/nemotron-3-ultra-550b-a55b")
SECONDARY_MODEL  = os.getenv("NVIDIA_MODEL_SECONDARY", "nvidia/llama-3.3-nemotron-super-49b-v1")
FALLBACK_MODEL   = os.getenv("NVIDIA_MODEL_FALLBACK",  "nvidia/llama-3.1-nemotron-70b-instruct")"""

new_config = """# ── Config ────────────────────────────────────────────────────
PRIMARY_MODEL    = os.getenv("PRIMARY_MODEL",   "moonshotai/kimi-k3")
PRIMARY_API_KEY  = os.getenv("PRIMARY_API_KEY", "")
PRIMARY_API_URL  = os.getenv("PRIMARY_API_URL", "https://api.moonshot.cn/v1/chat/completions")

SECONDARY_MODEL  = os.getenv("SECONDARY_MODEL", "deepseek-ai/deepseek-v4-flash-0731")
SECONDARY_API_KEY= os.getenv("SECONDARY_API_KEY", "")
SECONDARY_API_URL= os.getenv("SECONDARY_API_URL", "https://api.deepseek.com/chat/completions")

FALLBACK_MODEL   = os.getenv("FALLBACK_MODEL",  "meta/muse-glimmer-30b")
FALLBACK_API_KEY = os.getenv("FALLBACK_API_KEY", "")
FALLBACK_API_URL = os.getenv("FALLBACK_API_URL", "https://api.together.xyz/v1/chat/completions")"""

code = code.replace(old_config, new_config)

# Replace build_fix_prompt
old_build_prompt_start = """MAX_FILE_CHARS = 200_000 # Maximum source content sent to the AI model

def build_fix_prompt(file_path: str, file_content: str,"""

new_build_prompt = """MAX_FILE_CHARS = 200_000 # Maximum source content sent to the AI model

def build_primary_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\\n"
    return f\"\"\"You are the Primary AI Fix Engine (Moonshot Kimi). Fix ALL vulnerabilities strictly.
FILE: {file_path}
VULNERABILITIES TO FIX:
{vuln_list}
CURRENT FILE CONTENT:
```
{file_content}
```
OUTPUT RULES:
- Output ONLY raw source code — zero other text
- Do NOT wrap in markdown fences (no ```)
- First line of output = first line of the fixed file\"\"\"

def build_secondary_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\\n"
    return f\"\"\"You are the Secondary AI Fix Engine (DeepSeek V4).
FILE: {file_path}
VULNS:
{vuln_list}
CODE:
```
{file_content}
```
Rule: Return ONLY the raw fixed code. No explanation. No formatting.\"\"\"

def build_fallback_prompt(file_path: str, file_content: str, findings: list[dict]) -> str:
    vuln_list = ""
    for i, f in enumerate(findings, 1):
        vuln_list += f"\\n{i}. Line {f.get('line_start','?')}-{f.get('line_end','?')}: [{f.get('severity')}] {f.get('title','')}\\n"
    return f\"\"\"You are the Fallback Fix Engine (Muse Glimmer).
Fix this code.
FILE: {file_path}
VULNS:
{vuln_list}
CODE:
```
{file_content}
```
Return just the raw code.\"\"\"

def build_fix_prompt(file_path: str, file_content: str,"""

code = code.replace(old_build_prompt_start, new_build_prompt)

# Replace call_nim
old_call_nim = """def call_nim(prompt: str, model: str, max_tokens: int = 4096) -> tuple[str, float]:
    \"\"\"
    Call NVIDIA NIM. Returns (fixed_content, confidence).
    Confidence is estimated from response quality.
    \"\"\"
    try:
        r = httpx.post(
            NVIDIA_API_URL,
            headers={
                "Authorization": f"Bearer {NVIDIA_API_KEY}",
                "Content-Type":  "application/json",
            },"""
new_call_nim = """def call_llm(prompt: str, model: str, api_url: str, api_key: str, max_tokens: int = 4096) -> tuple[str, float]:
    \"\"\"
    Call the LLM API. Returns (fixed_content, confidence).
    \"\"\"
    try:
        r = httpx.post(
            api_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type":  "application/json",
            },"""
code = code.replace(old_call_nim, new_call_nim)

# Fix NIM error logging
code = code.replace('log.error(f"NIM HTTP {e.response.status_code}: {e.response.text[:200]}")', 'log.error(f"API HTTP {e.response.status_code}: {e.response.text[:200]}")')
code = code.replace('log.error(f"NIM call error: {e}")', 'log.error(f"API call error: {e}")')
code = code.replace('log.warning(f"  NIM returned explanation instead of code', 'log.warning(f"  API returned explanation instead of code')

# Replace try_with_fallback
old_fallback = """def try_with_fallback(prompt: str, max_tokens: int = 4096) -> tuple[str, float, str]:
    \"\"\"
    Try primary model first. If quality is poor, use secondary, then fallback.
    Returns (content, confidence, model_used)
    \"\"\"
    # 1. Primary
    content, confidence = call_nim(prompt, PRIMARY_MODEL, max_tokens)
    if confidence >= MIN_CONFIDENCE and content:
        return content, confidence, PRIMARY_MODEL

    log.warning(f"Primary model confidence {confidence:.0%} — trying secondary {SECONDARY_MODEL}")
    
    # 2. Secondary
    content2, confidence2 = call_nim(prompt, SECONDARY_MODEL, max_tokens)
    if confidence2 >= MIN_CONFIDENCE and content2:
        return content2, confidence2, SECONDARY_MODEL

    log.warning(f"Secondary model confidence {confidence2:.0%} — trying fallback {FALLBACK_MODEL}")

    # 3. Fallback
    content3, confidence3 = call_nim(prompt, FALLBACK_MODEL, max_tokens)
    if confidence3 > max(confidence, confidence2) and content3:
        return content3, confidence3, FALLBACK_MODEL

    # Return whichever was best
    best_conf = max(confidence, confidence2, confidence3)
    if best_conf == confidence and content:
        return content, confidence, PRIMARY_MODEL
    elif best_conf == confidence2 and content2:
        return content2, confidence2, SECONDARY_MODEL
    else:
        return content3, confidence3, FALLBACK_MODEL"""

new_fallback = """def try_with_fallback(file_path: str, file_content: str, findings: list[dict], max_tokens: int = 4096) -> tuple[str, float, str]:
    \"\"\"
    Try primary model first. If quality is poor, use secondary, then fallback.
    Returns (content, confidence, model_used)
    \"\"\"
    p1 = build_primary_prompt(file_path, file_content, findings)
    p2 = build_secondary_prompt(file_path, file_content, findings)
    p3 = build_fallback_prompt(file_path, file_content, findings)

    # 1. Primary
    content, confidence = call_llm(p1, PRIMARY_MODEL, PRIMARY_API_URL, PRIMARY_API_KEY, max_tokens)
    if confidence >= MIN_CONFIDENCE and content:
        return content, confidence, PRIMARY_MODEL

    log.warning(f"Primary model confidence {confidence:.0%} — trying secondary {SECONDARY_MODEL}")
    
    # 2. Secondary
    content2, confidence2 = call_llm(p2, SECONDARY_MODEL, SECONDARY_API_URL, SECONDARY_API_KEY, max_tokens)
    if confidence2 >= MIN_CONFIDENCE and content2:
        return content2, confidence2, SECONDARY_MODEL

    log.warning(f"Secondary model confidence {confidence2:.0%} — trying fallback {FALLBACK_MODEL}")

    # 3. Fallback
    content3, confidence3 = call_llm(p3, FALLBACK_MODEL, FALLBACK_API_URL, FALLBACK_API_KEY, max_tokens)
    if confidence3 > max(confidence, confidence2) and content3:
        return content3, confidence3, FALLBACK_MODEL

    # Return whichever was best
    best_conf = max(confidence, confidence2, confidence3)
    if best_conf == confidence and content:
        return content, confidence, PRIMARY_MODEL
    elif best_conf == confidence2 and content2:
        return content2, confidence2, SECONDARY_MODEL
    else:
        return content3, confidence3, FALLBACK_MODEL"""
code = code.replace(old_fallback, new_fallback)

# Update the call in run_ai_fix_engine
old_call = """            if is_requirements:
                prompt = build_sca_prompt(file_path, file_content, findings)
            else:
                prompt = build_fix_prompt(file_path, file_content, findings)

            # Call NIM with fallback
            fixed_content, confidence, model_used = try_with_fallback(
                prompt,
                max_tokens=max(2048, len(file_content.split()) * 3)
            )"""

new_call = """            # Call LLM with fallback
            fixed_content, confidence, model_used = try_with_fallback(
                file_path, file_content, findings,
                max_tokens=max(2048, len(file_content.split()) * 3)
            )"""
code = code.replace(old_call, new_call)

with open("ai-engine/fix_engine.py", "w") as f:
    f.write(code)

print("Patch completed!")
