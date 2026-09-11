with open(".env.example", "r") as f:
    env = f.read()

old_env = """# ── AI Engine — NVIDIA NIM ────────────────────────────────────
NVIDIA_API_KEY=your_nvidia_api_key_here
NVIDIA_MODEL=nvidia/nemotron-3-ultra-550b-a55b
NVIDIA_MODEL_SECONDARY=nvidia/llama-3.3-nemotron-super-49b-v1
NVIDIA_MODEL_FALLBACK=nvidia/llama-3.1-nemotron-70b-instruct"""

new_env = """# ── AI Engine — Multi-Model Fallback ──────────────────────────
PRIMARY_MODEL=moonshotai/kimi-k3
PRIMARY_API_KEY=your_moonshot_api_key_here
PRIMARY_API_URL=https://api.moonshot.cn/v1/chat/completions

SECONDARY_MODEL=deepseek-ai/deepseek-v4-flash-0731
SECONDARY_API_KEY=your_deepseek_api_key_here
SECONDARY_API_URL=https://api.deepseek.com/chat/completions

FALLBACK_MODEL=meta/muse-glimmer-30b
FALLBACK_API_KEY=your_together_api_key_here
FALLBACK_API_URL=https://api.together.xyz/v1/chat/completions"""

if old_env in env:
    env = env.replace(old_env, new_env)
    with open(".env.example", "w") as f:
        f.write(env)
    print(".env.example updated!")
else:
    print("Could not find the block to replace in .env.example")
