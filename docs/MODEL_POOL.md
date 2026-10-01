# AI model pool

The owner selected **OpenRouter only**, restricted to the seven free variants
below. All seven appeared in the [official catalog](https://openrouter.ai/api/v1/models)
with zero prompt/completion prices on 1 October 2026. Catalog presence does
not establish account access, availability or acceptable fixes. Earlier
direct-provider compatibility results do not validate these new routes.
The pool improves proposal availability within the existing Python SAST scope.
It does not promise every finding can be fixed or every proposed patch works.

## Private configuration

| Priority | Model | Exact API ID |
| --- | --- | --- |
| 1 | NVIDIA Nemotron 3 Ultra | `nvidia/nemotron-3-ultra-550b-a55b:free` |
| 2 | Poolside Laguna S 2.1 | `poolside/laguna-s-2.1:free` |
| 3 | NVIDIA Nemotron 3.5 Lightning | `nvidia/nemotron-3.5-lightning:free` |
| 4 | Cohere North Mini Code | `cohere/north-mini-code:free` |
| 5 | Qwen3.8 27B | `qwen/qwen3.8-27b:free` |
| 6 | Google Gemma 4 26B A4B | `google/gemma-4-26b-a4b-it:free` |
| 7 | Google Gemma 4 31B | `google/gemma-4-31b-it:free` |

Set the key privately in the server's `.env`. Select an ordered subset if
desired; omitting `OPENROUTER_MODELS` selects the table order, while an
explicitly empty list disables calls. Duplicates are removed and any other
model ID, including paid variants, is rejected without logging its value.

```dotenv
OPENROUTER_API_KEY=<private-replacement-key>
OPENROUTER_MODELS=nvidia/nemotron-3-ultra-550b-a55b:free,poolside/laguna-s-2.1:free
AI_MAX_MODEL_ROUTES_PER_FILE=4
AI_MODEL_FAILURE_COOLDOWN_SECONDS=60
AI_WORKER_CONCURRENCY=1
```

An absent/empty `OPENROUTER_API_KEY` disables calls, even if old provider keys
remain. Numbered routes, direct NVIDIA and PRIMARY/SECONDARY/FALLBACK variables
are ignored. The endpoint is fixed to
`https://openrouter.ai/api/v1/chat/completions`. The project configures no paid
fallback, plugins or automatic top-up. Requests set `provider.max_price` to
zero for prompt, completion and per-request pricing; see
[price constraints](https://openrouter.ai/docs/guides/routing/provider-selection#max-price).

Free routes have per-minute/account-wide daily limits and availability can
change. Inspect `GET /api/v1/key` privately for the account quota; see
[OpenRouter limits](https://openrouter.ai/docs/api-reference/limits).
Changing models or generating more keys does not create another account quota.
Source selected for remediation goes to OpenRouter and its providers.

Revoke any key pasted into chat and create its replacement in OpenRouter.
Enter the replacement privately on Kali, avoiding shell history:

```bash
cd ~/secureguard
python3 - <<'PY'
from getpass import getpass
from pathlib import Path
import os
os.umask(0o077)
key = getpass('New OpenRouter key: ')
if not key.strip() or any(c in key for c in '\r\n'):
    raise SystemExit('Invalid key')
path = Path('.env')
lines = [line for line in path.read_text().splitlines()
         if not line.startswith('OPENROUTER_API_KEY=')]
path.write_text('\n'.join(lines + ['OPENROUTER_API_KEY=' + key]) + '\n')
path.chmod(0o600)
print('Private key updated; no key printed')
PY
```

Gracefully stop/recreate the worker to load a changed key. Preserve queued
tasks and let active work finish; do not kill workers or purge the queue.

## Attempts, cooldowns and acceptance

- The default is at most four available routes per file, configurable from
  1 to 32. Each route retains up to three HTTP attempts. This bounds attempts,
  not a hard wall-clock deadline or a provider-wide token quota.
- A rate-limited route cools for its bounded `Retry-After` interval. Empty or
  unavailable responses cool for the configured failure interval. Cooling
  routes are skipped without consuming the per-file route budget.
- An OpenRouter 429 with `X-RateLimit-Remaining: 0` defers immediately and
  cools all routes sharing its key. Provider-specific limits without that
  platform signal retain normal model fallback.
- When cooling/unavailable routes remain and no candidate passes, Celery can
  defer until the earliest cooldown expires. Retries remain capped at five.
  Invalid code alone produces no proposal; it does not become a successful fix.
- Cooldowns, including the shared-key platform response, are **inside one worker process**, reset on
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
docker run --rm --env-file .env --user "$(id -u):$(id -g)" \
  -v "$PWD":/repo:ro -v "$PWD/reports":/reports \
  secureguard-orchestrator python /repo/scripts/check_model_pool.py \
  --output /reports/openrouter-model-check.json
```

This consumes one request per selected model from the free quota. The private
report records model ID, HTTP status, elapsed time and fixture
result. It omits API keys, raw responses, proposed code and real repository
content. Non-200 responses and failed syntax/interface/Bandit checks fail the
command; adjust the allowlist after reviewing those results privately.
Do not treat this one synthetic sample as a quality benchmark. Record real
reviewed PR outcomes before promoting a model in the fallback order.
