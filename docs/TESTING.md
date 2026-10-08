# Testing

The 1 October follow-up requires checking report finalization before AI,
rejection of late failed-status updates, receipt coverage in scan details and
generic API failures. Notification tests mock all external sends and verify
delivery outcomes and description/source omission; do not send test messages
to real recipients. Pre-pull the selected scanner versions and record digests
using [Next server session](NEXT_SERVER_SESSION.md), then verify native reports.

Run these checks on the Linux lab server after pulling the GitHub branch. Do
not run the application, builds, or tests on the development device.
Use [the server acceptance record](SERVER_ACCEPTANCE.md) to capture the exact
commit, build IDs, scan IDs, and redacted results.

## Pull the development branch on the server

Before pulling, check for server-only edits so they are not overwritten:

```bash
cd ~/secureguard
git status --short
git branch --show-current
git fetch github main
git merge --ff-only github/main
```

On this lab server, `github` points to GitHub and `origin` points to Gitea;
the deployment checkout is currently on `Features`. The commands above
fast-forward that checkout to GitHub `main`. Stop if `git status --short`
shows unexpected edits or the fast-forward fails; reconcile before proceeding.

## Static checks

```bash
python3 - <<'PY'
import ast
from pathlib import Path
for root in ("ai-engine", "cve-intel", "wazuh-proxy", "monitoring"):
    for path in Path(root).rglob("*.py"):
        ast.parse(path.read_text(), filename=str(path))
print("Python syntax OK")
PY
bash -n scripts/setup-kali.sh
docker compose config -q
```

Build the dashboard and service images:

```bash
docker compose build dashboard migrate orchestrator celery-worker cve-intel wazuh-proxy
```

Run the Python suite with the orchestrator image so its pinned application
dependencies are available:

```bash
docker run --rm --network none -v "$PWD":/repo:ro -w /repo \
  secureguard-orchestrator python -m unittest discover -s tests -v
```

After building, confirm migrations completed and the API routes load:

```bash
docker compose up -d
docker compose ps
docker compose logs --tail=100 migrate orchestrator cve-intel
docker compose exec -T orchestrator python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').status)"
docker compose exec -T cve-intel python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8001/health').status)"
```

The dashboard uses `dashboard/package-lock.json` and `npm ci` for reproducible
dependency installation. Its Vite 8 build uses Node 24 and serves the same
`/dashboard/` gateway path. JSX sources use `.jsx`; the HTML entry point is
`dashboard/index.html`. API overrides use `VITE_API_URL` and
`VITE_CVE_INTEL_URL`; the default is the gateway path. Set `PUBLIC_URL` during
the Docker build to change the asset base. Recreate the dashboard and verify
its generated assets, API requests and all tabs on Kali after a build change.

Prepare gateway TLS/login before startup. After moving the lab to HTTPS port
3000, verify login, assets, Grafana data and Gitea/Jenkins webhooks through
the new paths and confirm old ports are closed. The server audit/export
scripts read the private gateway credentials and trust the private lab CA;
see [Gateway checks](GATEWAY.md).

## OSV smoke test

```bash
mkdir -p reports
docker run --rm \
  -v "$PWD":/src:ro \
  -v "$PWD/reports":/reports \
  ghcr.io/google/osv-scanner:v2.4.0 \
  scan source --recursive --format sarif \
  --output-file /reports/osv.sarif /src
python3 -m json.tool reports/osv.sarif >/dev/null
```

In Jenkins, verify `OSV SCA`, `Upload Reports`, and `CVE Enrichment`. The console
must show `OSV OK`, `Uploading osv`, and HTTP 200.

OSV's documented exit **128** means no supported package sources were found.
The pipeline records an explicit `coverage=not_applicable` SARIF run and the
validator prints `NOT APPLICABLE`. This is missing ecosystem coverage, not
evidence that the repository has no vulnerable dependencies. Exit 0 or 1
requires a native report; every other exit code fails the OSV stage. See
[OSV return codes](https://google.github.io/osv-scanner/output/).

The `Validate Reports` stage uses `scripts/validate_scan_reports.py` and must
list valid Semgrep, Gitleaks, Trivy dependency, Grype, OSV, Dependency-Check,
Syft, Hadolint and ShellCheck reports. Bandit is required when the target has Python files. When
the target Docker image builds successfully, Dockle and Trivy image SARIF reports
are required too. Checkov and unconfigured Snyk remain optional. An invalid
required report or non-successful report upload must fail the Jenkins build.
Empty SARIF runs and explicitly failed scanner invocations are rejected.
The orchestrator should reject malformed report bodies and unknown scan IDs;
a valid SARIF report with zero results is accepted. Confirm Dockle SARIF
produces `iac` findings when it reports image-configuration issues. Syft's
SPDX inventory is accepted but does not create vulnerability records.
This contract needs confirmation on the lab server after the new Jenkinsfile
is pulled into Gitea.

## Dependency-Check and optional Snyk

After deploying a Jenkinsfile change, run a fresh scan on the server. Confirm
the `Dep-Check SCA` stage writes a nonempty `dep-check.sarif` and that
`Upload Reports` returns HTTP 200 for `dep-check`. A new `depcheck-cache`
volume needs its first NVD download, which can take longer than a later scan.
If data download fails or the report is missing, the stage should fail; inspect
the Dependency-Check error rather than treating a green pipeline as proof.
For this server, Jenkins #310 failed because NVD data could not be updated and
the CISA feed had a DNS error. Grype also waited on an Anchore data connection.
Confirm fresh data downloads or a valid persistent cache before expecting the
full report contract to pass. Check that the NVD key is configured without
printing it, and confirm Grype's new `grype-cache` volume is populated.
Check that `Update Trivy Database` finishes before the parallel scanners and
that both Trivy dependency and image reports are present when an image builds.
The 26 September #312 run could not download the Trivy DB from the default
mirror, so its two Trivy reports were missing; the next pipeline revision uses
a persistent cache and alternate official registries.
Build #313 found a protected key-file ownership mismatch: Jenkins writes as
UID 0 and Dependency-Check reads as UID 1000. Verify that the next run can
read the temporary mode-0600 file, then that the file is removed after the
stage and its value is absent from process arguments and console output.

For `BeyondBug/sietlms-moodle-` only, Dependency-Check excludes
`/src/public/lib/filestorage/tests/fixtures/*.zip`: those archive-parser test
fixtures include intentionally malformed and encrypted ZIP files. Other
source, dependencies and archives remain in scope. This exclusion is explicit
in Jenkins Prepare output; do not blanket-disable archive analysis or ignore
Dependency-Check errors. See [Dependency-Check CLI exclusions](https://jeremylong.github.io/DependencyCheck/dependency-check-cli/arguments.html).
Trivy source/image scans have explicit 25/30-minute timeouts; its persistent
cache retains the Java DB downloaded during the Moondream run.

Snyk is optional. If `SNYK_TOKEN` is configured in the server's private
`.env`, recreate Jenkins and verify a nonempty `snyk.sarif` plus HTTP 200
upload. Confirm the token value does not appear in the Jenkins console.

## Database verification

```sql
SELECT scanner, finding_class, severity, COUNT(*)
FROM findings
WHERE scan_run_id = (SELECT MAX(id) FROM scan_runs)
GROUP BY 1,2,3 ORDER BY 1,3;
```

OSV rows should use `scanner='osv'`, `finding_class='sca'`, and exact advisory IDs.

Export a completed scan for manual triage on the server:

```bash
python3 scripts/export_scan_triage.py <scan-id>
```

This creates private CSV files and a summary under
`reports/triage/scan-<scan-id>/`, which Git ignores. The review groups are
only candidates for duplicate findings. Fill package, version, image, owner,
disposition, and review date after checking the original advisory and affected
artifact. Do not commit the raw export; descriptions can contain secrets.

Audit current Gitea repositories, active push webhooks, and latest scan
records with:

```bash
python3 scripts/audit_scan_coverage.py
```

The report is saved to ignored `reports/coverage-snapshot.md`. It identifies
missing scans, nonterminal statuses, and scan history for repositories no
longer in the current Gitea list. Check webhook delivery history and trigger
fresh scans to confirm actual coverage.

## AI pull request validation

Jenkins scans `main`, `develop`, or `master` on push. Its completed build
does not test an AI branch opened afterward. For a PR, record its exact head
commit and run the applicable static checks, build, and service checks above
against that branch on the lab server. Confirm `git rev-parse HEAD` matches
the PR head before testing. Avoid replacing the running deployment checkout
with an unreviewed AI branch; use a separate checkout or worktree on the
server for branch validation.

When a patch changes a service contract, check the real client as well as the
service health endpoint. In particular, a Wazuh proxy patch must remain
reachable from Grafana through the Compose network and must work with the
Wazuh manager's certificate. Compare the original finding with a new scan
of the PR branch. See [AI pull request review](AI_PR_REVIEW.md).

## Configured model smoke test

Recreate containers after changing `.env`, because a restart does not reload the
environment. Confirm only non-secret values with `printenv MODEL_1` and make a
small chat-completions request from the server if model calls are enabled.
Both ordinary OpenAI-shaped objects and Gemini's one-element array responses
are supported.

## Next deployment gates

Follow [Next server session](NEXT_SERVER_SESSION.md) for the ordered backup,
Jenkins bootstrap, migrations, trigger/hook migration and acceptance run.
Prepare private Jenkins files before recreating CI/monitoring. Rebuild images
so the new Bandit validation dependency is available. New migrations add
artifact fields and accepted report receipts without backfilling historical
coverage.

The expanded suite includes API tests for malformed uploads, incomplete
completion, idempotent retries, conflicting reports and complete contracts,
plus candidate validation and private Jenkins preparation. Run it on Kali;
the older 33-test result does not cover these additions. Confirm representative
native reports retain critical severity, advisory ID and available package/
version/image metadata. Verify a missing conditional Bandit/image report cannot
be bypassed through the completion endpoint.

For AI PR-head acceptance, use the administrator parameters `REVIEW_AI_PR`,
`REVIEW_REPO_URL`, `REVIEW_BRANCH=secureguard/scan-N-fixes` and exact
`REVIEW_COMMIT_SHA`. That mode must not queue another AI proposal. Check the
recorded target SHA and shared pipeline SHA, then review runtime clients.
Run the controlled retry/fallback fixture on the server and verify failures
leave findings open; follow [AI quality](AI_RATE_LIMITS_AND_QUALITY.md).

Inspect Falco logs after the modern eBPF change. Require a persistent running
sensor and a controlled event visible through its exporter/Grafana, not merely
a zero-valued dashboard panel. The previous inspected engine was `nodriver`;
its inactive state did not prove a kernel-driver incompatibility. See
[Falco kernel sources](https://falco.org/docs/concepts/event-sources/kernel/).

After all target scans, run coverage with `--pipeline-commit` and
`--require-complete`. After manual triage, run `check_triage.py`. Neither tool
substitutes for delivered hooks, patch review or verified exception evidence.

## Follow-up code review fixes

Required scanner commands now preserve execution failures instead of piping
through `tail` or discarding nonzero exits. Bandit installation/scanning uses
fail-fast shell execution and the same pinned version as candidate validation.
Configured Snyk accepts only completed-scan exits 0/1 and uses `--fail-fast`;
its error/unsupported-project exits fail the stage. Checkov uses its documented
soft-fail setting for findings while preserving command execution failures.
See [Snyk test semantics](https://docs.snyk.io/developer-tools/snyk-cli/commands/test),
[Checkov soft fail](https://www.checkov.io/2.Basics/Hard%20and%20soft%20fail.html),
and [Dockle exit behavior](https://github.com/goodwithtech/dockle#specify-exit-code).

On Kali verify a failing scanner command fails its stage even when a partial
report exists. Restricted execution logs for Semgrep, Gitleaks, Checkov and
Trivy source scans stay in the temporary Jenkins workspace and are removed
by cleanup; no raw scanner output is copied into public acceptance records.
An execution success still does not establish that every language/file was
analyzed; review native coverage and parser warnings separately.

New API checks require trusted Gitea coordinates and an exact target SHA,
return 422 for malformed input/IDs, and reject AI queuing for incomplete or
failed scans. A failed scan cannot be relabeled complete; start a new scan.
After restart, verify metric labels use the actual repository and the active
scan gauge restores unfinished scan counts. Expanded server tests include
these API checks and restore-manifest preflight; they have not run locally.
Database connection construction now handles special characters in environment
passwords, and SQLAlchemy error logs hide bound finding/report parameters.
Verify connectivity using private configuration after recreating services.

## Dockerfile and shell lint acceptance

Rebuild Jenkins before using this stage. On Kali, pre-pull the versioned images:

```bash
docker pull hadolint/hadolint:v2.15.1-debian
docker pull koalaman/shellcheck:v0.11.0
```

Run the expanded suite and a fresh Jenkins scan. Verify both SARIF reports,
HTTP 200 uploads and accepted report receipts, including a repository with
no applicable files. It must record `not_applicable`, zero selected files and
successful adapter execution, rather than silently omit a tool. On a private
fixture branch, include a Dockerfile with an unversioned base and a shell
script with an unquoted expansion; confirm rule IDs, actual paths (including
spaces), line numbers and `quality` class in the API and PR conversation.
Remove one required lint report and confirm completion fails; reject malformed
native JSON, execution exit codes above 1, timeouts and inconsistent
not-applicable claims. Verify cancellation leaves no labeled child containers.
Lint findings do not imply a CVE or CVSS score. See [scope](SCANNERS.md).

The Grafana scanner chart now uses one grouped query for all scanner labels.
Recheck its query and rendered legend on Kali; the previous 32-query acceptance
count does not describe this updated dashboard. Verify INFO/UNKNOWN filters
and severity totals in the findings UI. These changes have not run locally.

## Finding accuracy presentation

On the product/finding-accuracy branch, check category + severity + review
filters together and paginate through results. Quality warnings remain in raw
counts and can be viewed separately. Search supports advisory IDs, packages and
images, with literal wildcard handling. Missing historical categories are unknown.
Expand a finding to inspect package/version/image metadata and review evidence.
Missing CVSS is “Not reported”; a real zero is displayed as zero. No category,
severity or scanner agreement automatically confirms exploitability.

Select a scan with a failed AI task: its AI state and task ID must be visible
independently of scanner completion, with findings still accessible. These
changes do not alter review dispositions, credentials or enqueue AI jobs.
