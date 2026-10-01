# AI rate limits and patch quality

The AI worker proposes changes only for open medium, high, or critical Python
SAST findings. It does not automatically fix dependency, image, secret, or
infrastructure findings. A `WIP:` pull request is a proposal, not a resolved
finding. See [AI PR review](AI_PR_REVIEW.md) for the release decision.

## Rate limits

The worker reserves one task per execution slot (`worker_prefetch_multiplier=1`)
so a single worker does not hold four additional proposals while other work
waits. This is not a global provider quota: configured concurrency and each
provider's account limits still apply.

If a later file exhausts provider availability after earlier files have passed
the candidate gates, the worker publishes those earlier changes as a `WIP:`
proposal. It reports the count of deferred files in the PR and task result;
their findings remain open. If no file has an acceptable change, normal
bounded Celery deferral still applies. A partial proposal does not schedule
an automatic follow-up or establish that the proposed fixes work.

- Configure `OPENROUTER_API_KEY` and order the approved `:free` IDs in
  `OPENROUTER_MODELS` in the server's `.env`. Other providers are disabled. The example
  keys are blank, so a copied example does not call a provider accidentally.
- The lab starts one AI worker process by default
  (`AI_WORKER_CONCURRENCY=1`). Increase this only after measuring the actual
  provider quota. Celery's task rate limit is per worker, so a worker count
  matters when applying a shared API quota.
- For HTTP 429 and temporary 5xx responses, the worker makes up to three
  attempts. It uses `Retry-After` when present (seconds or HTTP date), with a
  bounded delay (at most one hour), and uses exponential backoff with jitter otherwise. If a
  requested wait exceeds a minute, it tries another available configured model instead
  of holding a worker idle. Error bodies are not logged because they may
  contain source or credentials.
- If usable routes are cooling or temporarily unavailable, Celery defers the whole proposal
  task until the earliest recorded route cooldown expires, up to five retries. No branch
  is pushed before the full proposal is assembled, so this retry starts from
  the scan commit. A task that still cannot call a model ends in failure and
  leaves findings open for a later manual rerun.
- All selected free models share OpenRouter account limits. An OpenRouter 429
  with `X-RateLimit-Remaining: 0` defers immediately and cools every route using
  the same key, instead of retrying each model. Cooldowns remain process-local;
  restart resets them. Provider-specific 429s retain model fallback. Watch the worker logs
  for `rate limited`, `retry`, and final Celery failure; do not infer AI
  success from the Jenkins build, which only queues the task.

## Getting a useful fix

1. Start with a specific finding whose affected Python file and scan commit
   can be verified. The worker rejects a clone if the target branch has moved
   beyond that commit. Trigger a fresh scan when that happens.
2. The prompt includes finding ID, rule/CWE, location, title, and bounded
   description alongside the source file. It asks for a minimal patch that
   preserves public behavior and avoids invented APIs or credentials.
3. A model response must be changed Python code, parse successfully, and
   retain at least 70% of the original file's line count. Invalid, unchanged,
   or heavily shortened output is sent to the next model. These gates cannot
   establish that the vulnerability is fixed or the service still works.
4. If no model returns acceptable code, the task reports `no_proposal` with
   a reason. The finding remains open. Improve the finding context or handle
   it manually; do not treat an empty proposal as a successful fix.
5. Review the full diff and every scanner finding in the PR conversation.
   On the **PR head**, run applicable checks and rescan on the lab server.
   Verify the original finding is addressed and the real service/client
   behavior remains correct before approving or merging.

## Server verification

After pulling this change, recreate the worker so it reads the new `.env`
and Compose concurrency. Cause one controlled 429 from a mock endpoint or
quota-limited test account and confirm the wait/deferred task is visible
without a token in logs. Exercise one malformed model response followed by
a valid fallback response. Then review one real PR head and its fresh scan.
Record the worker task ID, scan ID, model used, PR head, and decision in the
[server acceptance record](SERVER_ACCEPTANCE.md). Do not run these checks on
the development laptop.

## Additional candidate gates prepared on 30 September

Candidates must retain existing Python class/function argument interfaces.
For eligible Bandit findings the worker parses both original and proposed text
using pinned Bandit 1.9.4 with `--ignore-nosec`. Original target rules must
reproduce, all target rules must disappear, and medium/high rule counts must
not increase. Missing validation rejects the candidate. A rejected candidate
provides a short diagnostic to the next configured model. Source is parsed,
not imported or executed; runtime behavior still needs server/client review.
Non-Bandit proposals retain manual review/rescan requirements.

Repository origins and paths are validated before Git; temporary askpass keeps
tokens out of command arguments/remotes. PRs target the scanned base branch.
Incomplete whole-scan conversation publication leaves findings open. Accepted
proposals still mean `pr_opened`, not `fixed`.

Rebuild the application images before using these gates. Run the expanded
Python suite and the controlled `scripts/check_ai_failure_modes.py` fixture on
Kali as described in [Next server session](NEXT_SERVER_SESSION.md). The fixture
uses real Celery/Redis scheduling on a unique queue with a local fake provider;
it checks deferred 429 exhaustion and invalid-output fallback without database
changes or PR publication. The fixture passed on Kali on 1 October. It does
not establish real-provider or real-patch acceptance.

## Historical pool and current free allowlist

The earlier pool supported numbered and direct NVIDIA routes. Those credentials
are now ignored: only the seven approved OpenRouter free variants are permitted.
The worker skips cooling routes, bounds attempts per file and rejects explicitly truncated,
filtered, refusal or tool-call responses. Cooldowns are process-local and
reset on restart; keep the single-worker lab default. Configuration, limitations
and the Kali-only synthetic compatibility check are in [Model pool](MODEL_POOL.md).
Before this provider change, three routes passed synthetic compatibility checks;
other routes returned an observed 429 or timeout. See the dated acceptance
record for the exact models. Compatibility does not prove patch correctness.

## Interface and source integrity follow-up

The interface gate also retains optional/required argument shape, decorators,
class bases, annotations and public definitions inside module/class conditions.
Function-local helpers may change. Default values may change while optionality
is preserved, because a security fix can require a different default; reviewers
must still assess the behavior change. Non-UTF-8 source is skipped instead of
silently dropping undecodable bytes. Those findings stay open for manual work.
These follow-up checks were prepared without running tests on the laptop.
File resolution also rejects symlinks and `.git` metadata. The final write
boundary repeats interface checks and uses strict UTF-8, so callers cannot
bypass the proposal validation through the file writer.

## Observed semantic rejection on 1 October

The real sg-bench PR #1 passed its exact-head scanner run but changed pickle
input to JSON without a client/data migration and used plain SHA-256 for
password hashing. It was rejected without merging; its 16 proposed finding
records were reopened. VigilentOps PR #18 was also rejected, with five proposal
records reopened, because its unchanged head retained B107/B310 findings.

The candidate and file-write boundaries now reject those two observed
substitutions. The input-format check recognizes imported aliases; the
password check recognizes weak-to-fast-digest replacements in functions with
password-like parameters. These bounded AST checks do not establish general
semantic equivalence or detect every unsafe cryptographic implementation.
Hash/input migrations still need explicit client/data review and server checks.
