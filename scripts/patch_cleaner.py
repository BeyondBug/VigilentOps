import re
with open("ai-engine/fix_engine.py", "r") as f:
    code = f.read()

# 1. Update the prompts to ENCOURAGE markdown fences so we can reliably extract the code
old_primary_rules = """OUTPUT RULES:
- Output ONLY raw source code — zero other text
- Do NOT wrap in markdown fences (no ```)
- First line of output = first line of the fixed file\"\"\""""

new_primary_rules = """OUTPUT RULES:
- You MUST wrap your final fixed code in a single markdown block (```)
- The markdown block must contain the FULL file content, not just a snippet.\"\"\""""
code = code.replace(old_primary_rules, new_primary_rules)

old_sec_rules = """Rule: Return ONLY the raw fixed code. No explanation. No formatting.\"\"\""""
new_sec_rules = """Rule: Return the FULL fixed code wrapped in a markdown block (```).\"\"\""""
code = code.replace(old_sec_rules, new_sec_rules)

old_fall_rules = """Return just the raw code.\"\"\""""
new_fall_rules = """Return the code wrapped in ```\"\"\""""
code = code.replace(old_fall_rules, new_fall_rules)

# 2. Update call_llm to extract the markdown block or strip the thoughts
old_extract = """        # Strip accidental markdown fences
        content = re.sub(r"^```[\w]*\n?", "", content)
        content = re.sub(r"\n?```\s*$", "", content)
        content = content.strip()"""

new_extract = """        # 1. Strip deepseek style <think> tags
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
        
        # 2. Extract code from markdown block (safest way to ignore reasoning)
        blocks = re.findall(r"```[\w]*\n(.*?)```", content, re.DOTALL)
        if blocks:
            # The last block is usually the final generated code
            content = blocks[-1].strip()
        else:
            # 3. Fallback: Try to strip Kimi's thinking prefix manually if no fences were used
            if "thinking process:" in content.lower():
                # Just brutally split and take the last part, assuming it might have separated it
                parts = re.split(r"(?:Here's a thinking process:|Thinking Process:)", content, flags=re.IGNORECASE)
                content = parts[-1].strip()

        # Standard fallback strip fences if any remain at the very edges
        content = re.sub(r"^```[\w]*\n?", "", content)
        content = re.sub(r"\n?```\s*$", "", content)
        content = content.strip()"""
code = code.replace(old_extract, new_extract)

with open("ai-engine/fix_engine.py", "w") as f:
    f.write(code)

print("Patch applied!")
