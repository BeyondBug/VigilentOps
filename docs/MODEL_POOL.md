# AI model pool

Prepared in code on 30 September; deployment and provider checks remain open.
The pool improves proposal availability within the existing Python SAST scope.
It does not promise every finding can be fixed or every proposed patch works.

## Private configuration

Numbered `MODEL_n`, `API_KEY_n`, `API_URL_n` entries are tried in numeric order.
Indices above nine now work. Up to 32 distinct routes are allowed. Incomplete
entries are ignored; duplicates with the same endpoint, model and key are
removed. Endpoints must be chat-completions URLs without embedded credentials,
query strings or fragments. Legacy PRIMARY/SECONDARY/FALLBACK entries are used
only when neither numbered nor NVIDIA pool routes are complete.

An optional explicit NVIDIA allowlist shares one private key:

```dotenv
NVIDIA_NIM_API_KEY=<private-key>
NVIDIA_NIM_MODELS=<verified-model-id>,<another-verified-model-id>
AI_MAX_MODEL_ROUTES_PER_FILE=4
AI_MODEL_FAILURE_COOLDOWN_SECONDS=60
AI_WORKER_CONCURRENCY=1
```

Replace placeholders before enabling. The NVIDIA list is appended after the
numbered routes and uses `https://integrate.api.nvidia.com/v1/chat/completions`.
The hosted endpoint and chat model catalog are described in NVIDIA's
[LLM API reference](https://docs.api.nvidia.com/nim/reference/llm-apis).
Select IDs actually available to your account. Catalog presence does not
establish code quality, entitlement or enough context for a project file.
The worker does not automatically enroll the entire catalog.

Put the strongest validated routes first and include an independent provider
early if available. Account/provider limits may affect several NVIDIA models;
switching models does not establish additional quota. Confirm actual limits
in your account as directed by NVIDIA's
[NIM FAQ](https://forums.developer.nvidia.com/t/nvidia-nim-faq/300317).
Keep all numbered keys, legacy keys and `NVIDIA_NIM_API_KEY` blank to disable
external model calls. Source selected for remediation goes to configured providers.

## Attempts, cooldowns and acceptance

- The default is at most four available routes per file, configurable from
  1 to 32. Each route retains up to three HTTP attempts. This bounds attempts,
  not a hard wall-clock deadline or a provider-wide token quota.
- A rate-limited route cools for its bounded `Retry-After` interval. Empty or
  unavailable responses cool for the configured failure interval. Cooling
  routes are skipped without consuming the per-file route budget.
- When cooling/unavailable routes remain and no candidate passes, Celery can
  defer until the earliest cooldown expires. Retries remain capped at five.
  Invalid code alone produces no proposal; it does not become a successful fix.
- Cooldowns are per model/endpoint/key **inside one worker process**, reset on
  restart and are not shared across workers. Keep the lab at one worker until
  shared quota scheduling is implemented and measured.
- Explicit truncation, content filtering, refusal, tool-call requests and
  non-text responses are rejected. Older responses without `finish_reason`
  remain compatible. Syntax/interface/Bandit gates still apply to candidates.
- A successful HTTP response is not an accepted fix. The exact PR head still
  needs a full diff review, targeted rescan and behavior checks on Kali.

A larger pool does not mean every route is tried for every file. Order the
pool deliberately and adjust the budget only within measured quotas. Logs
record models, cooldowns and rejections without response bodies or keys.

## Next Kali session

After configuring private values, rebuild the application images and recreate
the worker. Run the expanded suite and controlled Celery fixture first, as
described in [Next server session](NEXT_SERVER_SESSION.md).

Then run this **on Kali**, with outbound networking. It sends only a small
synthetic example to each configured provider, one request per route:

```bash
mkdir -p reports
docker run --rm --env-file .env \
  -v "$PWD":/repo:ro -v "$PWD/reports":/reports \
  secureguard-orchestrator python /repo/scripts/check_model_pool.py \
  --output /reports/model-pool-check.json
```

The private report records model ID, HTTP status, elapsed time and fixture
result. It omits API keys, raw responses, proposed code and real repository
content. Non-200 responses and failed syntax/interface/Bandit checks fail the
command; adjust the allowlist after reviewing those results privately.
Do not treat this one synthetic sample as a quality benchmark. Record real
reviewed PR outcomes before promoting a model in the fallback order.
