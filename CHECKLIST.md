# Project completion checklist

Status snapshot: 25 September 2026. This is a self-hosted **lab reference implementation**, not a production release. Update the evidence and checkboxes after each server run. Run builds, tests, and live checks on the lab server, following [docs/TESTING.md](docs/TESTING.md).

## Working and verified

- [x] Gitea push to `VigilentOps/main` triggers the shared Jenkins job.
- [x] Shared Jenkins pipeline loads from `VigilentOps/main` and mounts the central Semgrep rules for target scans. Jenkins #308 confirmed the rules were used.
- [x] Jenkins #308 completed and uploaded reports to orchestrator scan #235.
- [x] Orchestrator and CVE service health checks returned HTTP 200 after the latest API key rotation.
- [x] Server Docker builds for the orchestrator and dashboard succeeded; all 10 Python tests passed on the server.
- [x] Grafana `admin` login was verified on the server after the requested password change. Keep credentials out of this file.
- [x] The API key exposed in an older Jenkins log was rotated; build #308's full log did not contain the new key.
- [x] All 13 current Gitea repositories have a Jenkins webhook configured. This does **not** mean all 13 have been rescanned with the current pipeline.

## Required before calling the lab complete

### 1. Resolve and account for security findings

- [x] Prepare `scripts/export_scan_triage.py` to export private findings and suggested review groups on the server.
- [ ] Run that export for the latest complete scan and manually group records by advisory, package, version, image, and affected path. The API does not store package/version/image as separate fields, so the suggested groups are not a unique vulnerability count.
- [ ] Triage all open high findings, prioritizing reachable runtime dependencies and deployed container images. Scan #235 recorded **239 high**, **1,979 medium**, and **1,133 low** open records; 223 high records came from Trivy image scanning, and 8 each from Grype and Trivy dependency scanning.
- [ ] Upgrade, replace, or remove affected direct and transitive dependencies and base images where supported. Rebuild and rescan on the server. Record any finding that cannot be fixed, its impact, mitigation, owner, and review date.
- [ ] Review the 21 open Python SAST records from Bandit. Confirm each actual issue is fixed or documented with evidence; do not treat an AI proposal as a fix until its PR branch is reviewed and tested.
- [x] Define a lab release threshold and disposition rules in [docs/FINDING_TRIAGE.md](docs/FINDING_TRIAGE.md).
- [ ] Apply that policy to the latest scan; record all accepted exceptions and the remaining medium/low counts.

### 2. Make scanner results trustworthy

- [ ] Verify the prepared OWASP Dependency-Check change on the server: Jenkins #308 printed `dep-check no output`. The updated stage allows NVD data updates and fails on a missing SARIF report; tomorrow's server run must confirm a valid report and upload.
- [ ] Snyk is optional in the documented lab scope. If enabled, configure a valid `SNYK_TOKEN` in the server's private `.env`, recreate Jenkins, and verify a Snyk report without token disclosure. Jenkins #308 skipped it because the token was unset.
- [x] Prepare Jenkins report validation and upload failure handling. The required report contract and optional scanners are documented in [docs/TESTING.md](docs/TESTING.md); image scanning now follows a successful image build.
- [ ] Verify the report contract on the server: missing/invalid required output and non-200/201 upload must fail the build. Confirm optional scanner behavior on repositories without applicable files.
- [ ] Verify each expected scanner report is parsed and represented correctly in the orchestrator, including severity, advisory ID, affected file/package, and finding class.

### 3. Verify all target repositories

- [x] Prepare `scripts/audit_scan_coverage.py` for a read-only Gitea/webhook/scan inventory on the server.
- [ ] Inventory the 13 current Gitea repositories and confirm each webhook delivers a push event to Jenkins on an accepted branch (`main`, `develop`, or `master`).
- [ ] Run a fresh scan of **each** intended target with the current shared Jenkinsfile and rules. Record repo, branch, commit, Jenkins build, scan ID, result, and date. The current pipeline has only been confirmed on `VigilentOps`.
- [ ] Investigate old latest scan states: `Netflix-zuul` and `sietlms-moodle-` show `failed`; `Portfolio` and `browser-use` show `running`. Reconcile stale runs and verify new scans reach a terminal state.
- [ ] Reconcile the scan inventory with Gitea: scan history includes `ShadowPatch`, while the current Gitea list includes `SIET-Hackathon`. Confirm which repositories are in scope.
- [ ] Document that the shared Jenkinsfile and Semgrep rules come from `VigilentOps/main`. Other repositories' own Jenkinsfile/scanner files are older or absent; update those files only if they must run independently of the shared job.

### 4. Validate AI remediation safely

- [ ] Select a real open Python SAST finding and verify that the worker creates a `WIP:` Gitea PR against the correct repository and base commit, without exposing secrets.
- [ ] On a server-created PR, verify its conversation contains every numbered finding part for **all** scanner tools in that scan, with counts matching the database. Confirm secret snippets are absent and comment failures report a partial result.
- [ ] Review the entire proposed diff, map it to its finding, and run applicable checks against the **PR head** in a separate server checkout. Include service/client checks for any changed interface. Follow [docs/AI_PR_REVIEW.md](docs/AI_PR_REVIEW.md).
- [ ] Rescan the PR head, confirm the original finding is addressed and no material regression appears, then approve or reject it explicitly. Do not auto-merge an unreviewed AI patch.
- [ ] Confirm failed model calls, malformed responses, and unsafe or irrelevant patches leave the finding open and give a clear diagnostic.

### 5. Final lab acceptance run

- [ ] Pull the exact release commit onto the lab server; record GitHub and Gitea commit hashes and confirm they match.
- [ ] Run Compose validation, service builds, the Python suite, migrations, and health checks on the **server** using [docs/TESTING.md](docs/TESTING.md).
- [ ] Perform one end-to-end Gitea push → Jenkins → reports → database → dashboard check, and one reviewed AI PR branch check. Record build IDs, scan IDs, and the result in this checklist or a dated report.
- [ ] Verify Grafana dashboards and Wazuh/CVE integrations through their actual clients, not only service health endpoints.
- [ ] Update [README.md](README.md), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) to match the final deployed behavior. Mark the lab complete only when the required items above are checked with evidence.

## Additional gates before production exposure

- [ ] Replace the requested Grafana password before production use: that value appeared in prior repository history. Rotate any other historical secrets and review access to old Jenkins logs.
- [x] Disable webhook payload and contributed-variable printing in the shared Jenkinsfile.
- [ ] Replace the hardcoded Jenkins webhook token with a private credential, update all Gitea hooks, and verify that Jenkins accepts only trusted Gitea repository URLs before production exposure.
- [ ] Restrict published management ports to trusted networks; require appropriate authentication for dashboards, APIs, and management interfaces. Review Docker socket access and service privileges.
- [ ] Back up and test restore of PostgreSQL and persistent Gitea/Jenkins/Grafana volumes. Document recovery steps and retention.
- [ ] Pin and maintain scanner/container versions, define update cadence, and establish a monitored vulnerability exception process.
- [ ] Define ownership, alert routing, and response procedures for failed scans, unavailable services, new high findings, and AI PR review.

**Completion rule:** a green Jenkins build by itself is insufficient. The lab is complete when the required sections above have evidence, remaining findings have an explicit decision, and the final run succeeds on the exact release commit.
