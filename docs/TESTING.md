# Testing

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
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8001/health
```

The dashboard uses `dashboard/package-lock.json` and `npm ci` for reproducible
dependency installation.

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

The `Validate Reports` stage uses `scripts/validate_scan_reports.py` and must
list valid Semgrep, Gitleaks, Trivy dependency, Grype, OSV, Dependency-Check,
and Syft reports. Bandit is required when the target has Python files. When
the target Docker image builds successfully, Dockle and Trivy image reports
are required too. Checkov and unconfigured Snyk remain optional. An invalid
required report or non-successful report upload must fail the Jenkins build.
This contract needs confirmation on the lab server after the new Jenkinsfile
is pulled into Gitea.

## Dependency-Check and optional Snyk

After deploying a Jenkinsfile change, run a fresh scan on the server. Confirm
the `Dep-Check SCA` stage writes a nonempty `dep-check.sarif` and that
`Upload Reports` returns HTTP 200 for `dep-check`. A new `depcheck-cache`
volume needs its first NVD download, which can take longer than a later scan.
If data download fails or the report is missing, the stage should fail; inspect
the Dependency-Check error rather than treating a green pipeline as proof.

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
