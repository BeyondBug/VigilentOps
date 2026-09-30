# AI rate limits and patch quality

The AI worker proposes changes only for open medium, high, or critical Python
SAST findings. It does not automatically fix dependency, image, secret, or
infrastructure findings. A `WIP:` pull request is a proposal, not a resolved
finding. See [AI PR review](AI_PR_REVIEW.md) for the release decision.

## Rate limits

- Configure only models with a real `MODEL_n`, `API_URL_n`, and private
  `API_KEY_n` in the server's `.env`. Order them by preference. The example
  keys are blank, so a copied example does not call a provider accidentally.
- The lab starts one AI worker process by default
  (`AI_WORKER_CONCURRENCY=1`). Increase this only after measuring the actual
  provider quota. Celery's task rate limit is per worker, so a worker count
  matters when applying a shared API quota.
- For HTTP 429 and temporary 5xx responses, the worker makes up to three
  attempts. It uses `Retry-After` when present (seconds or HTTP date), with a
  bounded delay (at most one hour), and uses exponential backoff with jitter otherwise. If a
  requested wait exceeds a minute, it tries another configured model instead
  of holding a worker idle. Error bodies are not logged because they may
  contain source or credentials.
- If all usable routes are rate limited, Celery defers the whole proposal
  task for the provider's requested interval, up to five retries. No branch
  is pushed before the full proposal is assembled, so this retry starts from
  the scan commit. A task that still cannot call a model ends in failure and
  leaves findings open for a later manual rerun.
- Multiple configured models on one provider may share a quota. Put an
  independent provider second if continuity matters. Watch the worker logs
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
changes or PR publication. It does not establish real-provider or real-patch
acceptance. These new checks have not yet run.
