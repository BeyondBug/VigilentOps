# Next Kali session

These changes are prepared in GitHub. SSH connectivity returned on 1 October;
the new security, API, AI and recovery changes have **not**
passed a deployment or test run. Run every command below on Kali. Record the
exact hashes and results in a dated acceptance report. Do not run them on the
laptop. Keep raw logs, exports, credentials and backups off Git.

## 1. Preserve the current deployment

Wait for Jenkins and Celery work to finish. Inspect the checkout and remotes:

```bash
cd ~/secureguard
git status --short
git branch --show-current
git remote -v
git rev-parse HEAD
```

Stop if there are unexpected tracked edits; preserve and reconcile them before
pulling. Take a private backup of the current database, configuration and
persistent volumes using [Operations](OPERATIONS.md). The existing snapshots
remain available under `~/secureguard-backups/`; do not overwrite them.
The new `backup_lab.py` can be used after pulling code, **before** recreating
services or applying migrations. It requires the full lab stack's containers
and an idle Jenkins/Celery queue, pauses writers, then restarts them.

```bash
git fetch github main
git merge --ff-only github/main
git rev-parse HEAD
python3 scripts/backup_lab.py
```

Record the printed backup directory. Keep the pre-update image IDs available
for rollback and the isolated restore drill; do not prune them.

## 2. Prepare credentials before Compose

Keep the configured gateway login in `.env`. Its current username is
`BeyondBug` (case sensitive). Preparation copies that login into native Jenkins
and generates separate metrics and webhook credentials without printing them:

```bash
python3 scripts/prepare_jenkins_security.py
docker compose --profile ci --profile monitoring config -q
docker compose build --pull jenkins
docker compose build dashboard migrate orchestrator celery-worker cve-intel wazuh-proxy
docker pull hadolint/hadolint:v2.15.1-debian
docker pull koalaman/shellcheck:v0.11.0
python3 scripts/record_scanner_images.py --pull --output reports/scanner-images-20261001.json
```

Prepare the private files **before** recreating Jenkins or Prometheus. Do not
change Gitea hook tokens yet. The first updated pipeline run must initialize
the job's credential-backed trigger before those hooks are migrated.

Run the expanded Python suite using the built application image:

```bash
docker run --rm --network none -v "$PWD":/repo:ro -w /repo \
  secureguard-orchestrator python -m unittest discover -s tests -v
```

A failure is a deployment stop; fix it before continuing. No result from the
older 33-test run establishes that this expanded suite passes.
Keep the old scanner images and dependency caches. The version manifest
includes Dependency-Check 13; verify cache compatibility and native SARIF
before accepting a scan. The digest inventory proves availability only.

## 3. Migrate and deploy

The two new migrations retain historical findings and add artifact metadata,
report receipts and shared pipeline commit tracking. Historical rows remain
without receipts/metadata until a new scan supplies them.

```bash
docker compose stop orchestrator celery-worker cve-intel cve-worker
docker compose run --rm --no-deps migrate
docker compose --profile ci --profile monitoring up -d --build
docker compose ps
docker exec sg-gateway nginx -t
docker compose logs --tail=100 migrate orchestrator jenkins
```

Confirm migrations exit zero; both application health checks return 200;
Jenkins bootstrap installs the private realm, permission matrix and CSRF
protection; `BeyondBug` can use Jenkins through `/jenkins/`. Confirm anonymous
requests fail both at the gateway and directly on the Docker network. The
`sg-metrics` account may read metrics, but must not administer Jenkins.
All eight Prometheus targets and Grafana queries must work after this change.
Use [Testing](TESTING.md) and [Gateway](GATEWAY.md) for the wider checks.

```bash
python3 scripts/check_gateway_monitoring.py --output reports/gateway-monitoring-final.json
```

This verifies gateway authentication, all configured Prometheus targets and
every provisioned Grafana query's data frames. Browser rendering, WebSocket
and real event/scan checks remain separate.

## 4. Push Gitea and migrate hooks in order

Trust the lab CA for the existing HTTPS remote:

```bash
git config http.https://localhost:3000/.sslCAInfo "$PWD/secrets/gateway/ca.pem"
git push origin HEAD:main
```

Use the private Gitea token if Git prompts; never put it in the remote URL or
command line. The existing hook can start the first run while the job retains
its previous trigger configuration. If it cannot, launch one administrator
build with the same Gitea push variables (`REPO_URL`, `COMMIT_SHA`,
`BRANCH_REF=refs/heads/main`, `REPO_NAME`, `PUSHER`); do not loosen the URL or
commit checks. Confirm the job now uses credential ID `gitea-webhook-token`.
Then migrate and test hooks:

```bash
python3 scripts/manage_gitea_hooks.py
python3 scripts/manage_gitea_hooks.py --apply
python3 scripts/manage_gitea_hooks.py --test
```

A queued test delivery is not successful scan evidence. Record each delivery,
Jenkins build, checked out commit, scan ID and terminal result. Retrying only
failed targets is available with `--test --failed-only`. The interrupted
previous rerun command may have queued some builds; inspect the queue first.
Reject the old token internally without queuing a build; public trigger routes
must remain blocked. See [Token rotation](WEBHOOK_TOKEN_ROTATION.md).

## 5. Verify all 13 targets and report gates

Prior failures: Moondream (Trivy image timeout after Java DB download),
Netflix-Hystrix/Netflix-zuul/browser-use (OSV found no supported packages),
and sietlms-moodle- (malformed/encrypted archive test fixtures). Code fixes
are prepared; fresh successful scans are still required. OSV not applicable
is explicit coverage information, not a clean dependency scan. The new
Hadolint/ShellCheck stage must produce required reports for every new scan,
with explicit not-applicable receipts when files are absent. Verify real rule
IDs, paths, severity and quality classification as described in
[Testing](TESTING.md). Jenkins needs its rebuilt Python-enabled image.
Old scan receipts do not establish coverage by the new tools.

```bash
python3 scripts/audit_scan_coverage.py --pipeline-commit "$(git rev-parse HEAD)" \
  --require-complete --output reports/coverage-final.md
```

The audit compares the default-branch head, scanned commit and shared pipeline
commit. Investigate `PENDING` rows. Confirm the API stores each accepted report,
including zero findings, and rejects incomplete completion, malformed output,
conflicting uploads and uploads to finalized scans. Review package/version,
image, severity and advisory mappings from representative native reports.
Reports are finalized before enrichment and AI. A later enrichment/AI failure
may fail Jenkins while the accepted scan remains complete; record both results.
Verify notification delivery failures are visible, disabled channels are
explicit, and scan details distinguish no input from zero findings.

## 6. AI and finding review

Run the controlled AI retry/fallback fixture inside the newly built service
image. It uses a unique Redis queue, a local fake provider and temporary Git
fixture; it does not publish a PR or update findings:

Copy the fixture into the worker first, then run it:

```bash
docker cp scripts/check_ai_failure_modes.py sg-celery:/tmp/check_ai_failure_modes.py
docker compose exec -T celery-worker python /tmp/check_ai_failure_modes.py
```

Record deferred RETRY,
bounded FAILURE, invalid-output rejection and validated fallback. A fixture
pass still does not validate a real AI patch.

PR #18 is not accepted: its original B107/B310 findings survived the prior
rescan. Review/correct it or reject it explicitly; do not merge it unchanged.
Generate and review a new real proposal, then use the Jenkins administrator
parameters `REVIEW_AI_PR=true`, `REVIEW_REPO_URL`, `REVIEW_BRANCH` and exact
40-character `REVIEW_COMMIT_SHA` to scan its head. This mode suppresses another
AI task. Verify base branch, all numbered whole-scan finding comments, the
entire diff, service clients and disappearance of the original finding.

Export the fresh complete scan using its actual ID:

```bash
python3 scripts/export_scan_triage.py SCAN_ID --output reports/triage/final
```

Replace `SCAN_ID` with the numeric ID. Review every group and fill its owner,
disposition and evidence. Apply [Finding triage](FINDING_TRIAGE.md), then run:

```bash
python3 scripts/check_triage.py reports/triage/final
```

No automated tool may invent accepted exceptions or approve untested fixes.

## 7. Recovery, runtime monitoring and final record

Run `restore_lab_backup.py` against the new backup directory. It creates only
unique disposable containers/volumes with no network or published ports,
compares restored table counts and archive contents, then removes those
resources. It does not prove a full service recovery; rehearse restored Gitea,
Jenkins and Grafana access separately in an isolated stack.

Falco was configured as `nodriver` during inspection. The prepared modern eBPF
configuration needs a stable running container and a controlled event verified
through Falco → exporter → Prometheus/Grafana. A zero container panel does not
prove an active sensor. Check BTF/privileges and driver logs on Kali.

Finish with one real accepted-branch push through reports, database and UI,
one reviewed AI PR head scan, Grafana queries/WebSocket and HTTPS Git. Compare:

```bash
git rev-parse HEAD
git ls-remote github refs/heads/main
git ls-remote origin refs/heads/main
```

Update [CHECKLIST](../CHECKLIST.md) with evidence and limitations. Mark the lab
complete only when all required gates pass on this exact release commit.

## Follow-up verification

Include the follow-up scanner exit-code, API-input/AI-eligibility, startup
metrics and recovery-manifest fixes in the same acceptance run. Use a quiet
maintenance window for backups; idle checks do not prevent a different operator
from starting work. Required scanners must fail on execution errors even when
a partial report exists. Do not invoke remediation on historical scans without
new report receipts; rerun them first.

## Model-pool compatibility and real fix acceptance

Configure only account-verified model IDs in the private `.env`. Follow
[Model pool](MODEL_POOL.md) to run the synthetic compatibility fixture after
rebuilding images, the expanded suite and the controlled Celery checks.
Verify route budgets, cooldown expiry and rejection of truncated/refusal/tool
responses. Then create and review one real proposal, scan its exact head and
exercise affected clients before recording an accepted fix. Synthetic fixture
success alone does not meet that gate. Keep cooldown state at one worker;
provider-wide quota handling across workers remains future work.

Include interface regression cases for removed defaults, changed decorators,
class bases/annotations and conditional definitions. Verify non-UTF-8 files
are skipped with a diagnostic and unchanged finding status, not lossily
rewritten. Legitimate fixes needing interface changes require manual review.
