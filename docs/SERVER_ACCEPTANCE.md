# Server acceptance record

Use this on the Kali lab server after the GitHub changes are ready. Keep raw
finding exports, tokens, console logs, and credentials on the server; commit
only the redacted evidence table and decisions. The commands below are a
sequence, not results from the development device.

## 1. Deploy one exact commit

```bash
cd ~/secureguard
git status --short
git branch --show-current
git fetch github main
git merge --ff-only github/main
git rev-parse HEAD
git push origin HEAD:main
git ls-remote origin refs/heads/main
```

Stop if the checkout has unexpected edits, the merge is not a fast-forward,
or the hashes from the last two commands differ. The server checkout uses
`github` for GitHub and `origin` for Gitea. Record the exact hash below.

## 2. Run the application checks

Follow [Testing](TESTING.md) on the server: syntax, `docker compose config`,
service builds, Python suite, migration/startup, health endpoints, and OSV
smoke test. Record pass/fail and the relevant build or log reference. Start
the `ci` and `monitoring` profiles only after checking their private `.env`
settings. Do not paste secrets into this record.

Confirm a normal push registers the checked out commit, then use a disposable
job with a deliberately stale webhook commit to confirm Jenkins rejects the
mismatch before a scan record is created.

## 3. Prove the scanner contract

Run a new accepted-branch push on `VigilentOps`. Confirm Jenkins fetched this
Jenkinsfile from Gitea `main`, cloned the target at the webhook commit, and
registered that exact commit with the orchestrator. Confirm every required
report in [Testing](TESTING.md) exists, validates, uploads with HTTP 200 or
201, and has the expected scanner and finding class in the database.

The earlier Jenkins #308 / scan #235 is baseline evidence only. It predates
the current validator and did not produce a Dependency-Check report. The new
run must prove that stage produces SARIF. Snyk is optional; record whether it
was enabled. If an image build is skipped, record why and which image scanner
reports were absent. A successful pipeline with missing required reports is
an acceptance failure.

Use a controlled failure case to show a missing or malformed required report
fails `Validate Reports`, and a rejected upload fails `Upload Reports`.
Perform these cases in a disposable Jenkins job or branch so they do not
overwrite the release scan evidence.

## 4. Cover every repository

```bash
python3 scripts/audit_scan_coverage.py
```

Review the private `reports/coverage-snapshot.md` and each Gitea webhook's
recent deliveries. For each intended repository, trigger a fresh push on an
accepted branch, then capture its exact commit, Jenkins build, scan ID,
terminal status, and date in the table below. Check that the scan's commit is
the one Jenkins checked out. Resolve the old failed/running states and the
`ShadowPatch` / `SIET-Hackathon` inventory difference before declaring full
coverage.

## 5. Triage and review AI output

```bash
python3 scripts/export_scan_triage.py <latest-complete-scan-id>
```

Keep the CSV private. Apply [Finding triage](FINDING_TRIAGE.md) to every
review group; record owners and dispositions. Rebuild and rescan fixes. For
one real Python SAST finding, follow [AI PR review](AI_PR_REVIEW.md) on the
PR head in a separate server checkout. Verify the PR conversation has every
numbered finding part across all scanners, counts match stored findings,
redacted secret values stay absent, and a failed comment posts a partial
result. A queued AI task or a green base-branch build is not acceptance.
Follow [AI rate limits and patch quality](AI_RATE_LIMITS_AND_QUALITY.md) to
check a controlled 429, deferred retry, invalid-output fallback, and final
diagnostic without exposing a provider key.

## 6. Check clients and monitoring

Open the dashboard and confirm a new scan's reports and counts. Check Grafana
login and dashboards, Prometheus targets, CVE enrichment through the
dashboard/API client, and Grafana's Wazuh panels through the proxy. Record
the result of each client check, including a screenshot or non-secret log
reference when useful.

## Redacted evidence to fill after the server run

| Item | Result | Evidence / identifier | Date (IST) |
| --- | --- | --- | --- |
| GitHub and Gitea `main` hashes match | Pending | | |
| Compose config, builds, Python suite, migrations | Pending | | |
| API and CVE health, dashboard client | Pending | | |
| Required reports validate and upload | Pending | Jenkins build / scan ID: | |
| Dependency-Check SARIF and optional Snyk decision | Pending | | |
| Every intended repository has a fresh terminal scan | Pending | Private coverage snapshot: | |
| High/critical/secret and medium/low triage policy met | Pending | Private triage export: | |
| AI PR conversation and PR-head validation | Pending | PR / head commit / scan ID: | |
| AI 429 retry and invalid-output fallback | Pending | Worker task ID / redacted log: | |
| Grafana, Wazuh, CVE client checks | Pending | | |

Update [CHECKLIST.md](../CHECKLIST.md) only after the evidence is collected.
If any row fails, record the issue and rerun against the fixed commit.
