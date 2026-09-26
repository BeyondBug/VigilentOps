# Project completion checklist

Status snapshot: 26 September 2026. This is a self-hosted **lab reference implementation**, not a production release. Update the evidence and checkboxes after each server run. Run builds, tests, and live checks on the lab server, following [docs/TESTING.md](docs/TESTING.md). Today's server results and limitations are in [docs/ACCEPTANCE_2026-09-26.md](docs/ACCEPTANCE_2026-09-26.md).

## End-of-day handoff and next actions

- At handoff, GitHub `main`, Gitea `main`, and the Kali checkout matched at `b5766bf0b027e8e6a844c00342126487a44e4f13`. This documentation update will create a later commit; verify all three hashes again before release.
- Jenkins **#315** on scan **#241** was still running. Its Trivy database update passed and fresh SARIF contained 24 dependency findings and 3,473 image findings; Dockle SARIF contained 5 findings. Dependency-Check had downloaded 30,000 of about 398,000 NVD records. Report validation, upload, scan completion, and AI PR creation were **not yet verified**. Do not count this as a passing scan.
- The server's outbound NVD, CISA, and container-registry transfers have stalled or timed out repeatedly. The operator is working on server network reliability. First finish/inspect #315, then retry a complete scan only after the feeds are reachable. Keep required scanners fail-closed.
- **Next in order:** record #315's terminal result and the Dependency-Check error or valid SARIF; confirm all required reports upload and scan #241 reaches a terminal state; run and review one new AI PR with every scan finding in its conversation; then rescan all 13 current Gitea repositories and triage their fresh findings.
- The 50 older open AI PRs have no numbered finding comments. The user chose the detailed whole-scan conversation format for **future PRs only**; leave those older conversations unchanged. They still require ordinary review before any merge.
- Do not run builds or tests on the laptop. Make code changes here, push GitHub, update the Kali checkout, push Gitea from Kali, and test there. Keep credentials and raw findings off Git.

## Working and verified

- [x] Gitea push to `VigilentOps/main` triggers the shared Jenkins job.
- [x] Shared Jenkins pipeline loads from `VigilentOps/main` and mounts the central Semgrep rules for target scans. Jenkins #308 confirmed the rules were used.
- [x] Jenkins #308 completed and uploaded reports to orchestrator scan #235.
- [x] Orchestrator and CVE service health checks returned HTTP 200 after the latest API key rotation.
- [x] Server Docker builds for the orchestrator and dashboard succeeded; all 10 Python tests passed on the server.
- [x] Grafana `admin` login was verified on the server after the requested password change. Keep credentials out of this file.
- [x] The API key exposed in an older Jenkins log was rotated; build #308's full log did not contain the new key.
- [x] All 13 current Gitea repositories have a Jenkins webhook configured. This does **not** mean all 13 have been rescanned with the current pipeline.
- [x] On 26 September, the server built the changed services and Jenkins image, passed all 29 Python tests, and returned HTTP 200 for orchestrator, CVE, dashboard, and Jenkins endpoints at commit `fd458f4`.
- [x] At commit `b5766bf`, GitHub `main`, Gitea `main`, and the server checkout matched. The final documentation commit still needs the same check.

## Required before calling the lab complete

### 1. Resolve and account for security findings

- [x] Prepare `scripts/export_scan_triage.py` to export private findings and suggested review groups on the server.
- [x] Run the private export for latest complete scan #235: 3,351 records and 2,570 suggested review groups on the server.
- [ ] Manually group those records by advisory, package, version, image, and affected path. The API does not store package/version/image as separate fields, so the suggested groups are not a unique vulnerability count. Repeat on a fresh complete scan before release.
- [ ] Triage all open high findings, prioritizing reachable runtime dependencies and deployed container images. Scan #235 recorded **239 high**, **1,979 medium**, and **1,133 low** open records; 223 high records came from Trivy image scanning, and 8 each from Grype and Trivy dependency scanning.
- [ ] Upgrade, replace, or remove affected direct and transitive dependencies and base images where supported. Rebuild and rescan on the server. Record any finding that cannot be fixed, its impact, mitigation, owner, and review date.
- [ ] Review the 21 open Python SAST records from Bandit. Confirm each actual issue is fixed or documented with evidence; do not treat an AI proposal as a fix until its PR branch is reviewed and tested.
- [x] Define a lab release threshold and disposition rules in [docs/FINDING_TRIAGE.md](docs/FINDING_TRIAGE.md).
- [ ] Apply that policy to the latest scan; record all accepted exceptions and the remaining medium/low counts.

### 2. Make scanner results trustworthy

- [ ] Verify Dependency-Check SARIF and upload on the server. Jenkins #310 failed because NVD/CISA data was unreachable; the next run must confirm a populated cache, valid report, and upload.
- [x] Jenkins #315 completed the persistent Trivy DB update and produced valid SARIF 2.1.0 for dependencies (24 results) and the built image (3,473 results). Dockle produced valid SARIF with 5 results. Upload and stored-field checks remain open below.
- [x] Decide Snyk scope for the lab: optional and disabled; the server's `SNYK_TOKEN` is empty. If enabled later, configure a valid private token, recreate Jenkins, and verify its report without disclosure.
- [x] Prepare Jenkins report validation and upload failure handling. The required report contract and optional scanners are documented in [docs/TESTING.md](docs/TESTING.md); image scanning now follows a successful image build.
- [x] Prepare Dockle SARIF ingestion so image-configuration findings can reach the dashboard and AI PR conversation; verify the report and mapping on the server.
- [x] Prepare Jenkins to register the checked out target commit and reject a webhook commit mismatch before creating the scan record; verify this behavior on the server.
- [ ] Verify the report contract on the server: missing/invalid required output and non-200/201 upload must fail the build. Confirm optional scanner behavior on repositories without applicable files.
- [x] Verify #315 starts with clean generated reports and the NVD key file is owned by scanner UID 1000 with mode 0600 while Dependency-Check runs. No stale Trivy/Dependency-Check report was present at scan start.
- [ ] Verify the NVD key file is removed after the stage and an untrusted clone URL is rejected before checkout. Rotate the exposed NVD key after this run.
- [ ] Verify each expected scanner report is parsed and represented correctly in the orchestrator, including severity, advisory ID, affected file/package, and finding class.

### 3. Verify all target repositories

- [x] Prepare `scripts/audit_scan_coverage.py` for a read-only Gitea/webhook/scan inventory on the server.
- [x] Inventory 13 current Gitea repositories; each has an active push webhook (26 September audit).
- [ ] Confirm each webhook actually delivers a push event to Jenkins on an accepted branch (`main`, `develop`, or `master`).
- [ ] Run a fresh scan of **each** intended target with the current shared Jenkinsfile and rules. Record repo, branch, commit, Jenkins build, scan ID, result, and date. The current pipeline has only been confirmed on `VigilentOps`.
- [ ] Investigate old latest scan states: `Netflix-zuul` and `sietlms-moodle-` show `failed`; `Portfolio` and `browser-use` show `running`. Reconcile stale runs and verify new scans reach a terminal state.
- [ ] Reconcile the scan inventory with Gitea: scan history includes `ShadowPatch`, while the current Gitea list includes `SIET-Hackathon`. Confirm which repositories are in scope.
- [ ] Document that the shared Jenkinsfile and Semgrep rules come from `VigilentOps/main`. Other repositories' own Jenkinsfile/scanner files are older or absent; update those files only if they must run independently of the shared job.

### 4. Validate AI remediation safely

- [x] Prepare bounded 429/temporary-error handling, a single-worker lab default, exact scan-commit checks, better finding context, and model-output gates. See [AI rate limits and patch quality](docs/AI_RATE_LIMITS_AND_QUALITY.md).
- [x] The 29 server Python tests included simulated 429 deferral, invalid model-output fallback, finding-comment splitting, credential redaction, and partial comment-post failure.
- [x] Audit existing AI PR conversations: 50 older open PRs have no numbered finding comments. The user chose to apply the complete conversation requirement to future PRs only.
- [ ] On the server, verify a controlled 429/deferred task and invalid-output fallback; confirm final failures leave findings open and show a clear diagnostic.
- [ ] Select a real open Python SAST finding and verify that the worker creates a `WIP:` Gitea PR against the correct repository and base commit, without exposing secrets.
- [ ] On a server-created PR, verify its conversation contains every numbered finding part for **all** scanner tools in that scan, with counts matching the database. Confirm secret snippets are absent and comment failures report a partial result.
- [ ] Review the entire proposed diff, map it to its finding, and run applicable checks against the **PR head** in a separate server checkout. Include service/client checks for any changed interface. Follow [docs/AI_PR_REVIEW.md](docs/AI_PR_REVIEW.md).
- [ ] Rescan the PR head, confirm the original finding is addressed and no material regression appears, then approve or reject it explicitly. Do not auto-merge an unreviewed AI patch.
- [ ] Confirm failed model calls, malformed responses, and unsafe or irrelevant patches leave the finding open and give a clear diagnostic.

### 5. Final lab acceptance run

- [ ] Pull the exact release commit onto the lab server; record GitHub and Gitea commit hashes and confirm they match.
- [x] Verify interim commit `fd458f4` matched GitHub/Gitea and server checkout on 26 September. The final release commit must be checked again after scanner fixes.
- [x] Prepare a redacted [server acceptance record](docs/SERVER_ACCEPTANCE.md) and a coordinated [webhook token rotation procedure](docs/WEBHOOK_TOKEN_ROTATION.md).
- [ ] Run Compose validation, service builds, the Python suite, migrations, and health checks on the **server** using [docs/TESTING.md](docs/TESTING.md).
- [ ] Perform one end-to-end Gitea push → Jenkins → reports → database → dashboard check, and one reviewed AI PR branch check. Record build IDs, scan IDs, and the result in this checklist or a dated report.
- [x] Verify Grafana login/provisioning and actual Wazuh, CVE, and Prometheus panel queries via `/api/ds/query` on 26 September; each returned HTTP 200 with data frames and no datasource error.
- [ ] Update [README.md](README.md), [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) to match the final deployed behavior. Mark the lab complete only when the required items above are checked with evidence.

## Additional gates before production exposure

- [x] Prepare a [backup, recovery, ownership, and maintenance runbook](docs/OPERATIONS.md); its live checks and owner assignments remain open below.
- [x] On 26 September, create private PostgreSQL and Gitea/Jenkins/Grafana volume backups and restore the database/archives into disposable containers or volumes; row and entry counts matched. See [server evidence](docs/ACCEPTANCE_2026-09-26.md).
- [ ] Replace the requested Grafana password before production use: that value appeared in prior repository history. Rotate any other historical secrets and review access to old Jenkins logs.
- [ ] Rotate the NVD API key after the 26 September run; the old pipeline placed it in process arguments visible to server operators.
- [x] Disable webhook payload and contributed-variable printing in the shared Jenkinsfile.
- [ ] Replace the hardcoded Jenkins webhook token with a private credential, update all Gitea hooks, and verify that Jenkins accepts only trusted Gitea repository URLs before production exposure.
- [ ] Restrict published management ports to trusted networks; require appropriate authentication for dashboards, APIs, and management interfaces. Review Docker socket access and service privileges.
- [ ] Back up and test restore of PostgreSQL and persistent Gitea/Jenkins/Grafana volumes. Document recovery steps and retention.
- [ ] Pin and maintain scanner/container versions, define update cadence, and establish a monitored vulnerability exception process.
- [ ] Define ownership, alert routing, and response procedures for failed scans, unavailable services, new high findings, and AI PR review.

**Completion rule:** a green Jenkins build by itself is insufficient. The lab is complete when the required sections above have evidence, remaining findings have an explicit decision, and the final run succeeds on the exact release commit.
