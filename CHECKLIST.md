# Project completion checklist

Status snapshot: 30 September 2026. This is a self-hosted **lab reference implementation**, not a production release. Update the evidence and checkboxes after each server run. Run builds, tests, and live checks on the lab server, following [docs/TESTING.md](docs/TESTING.md). The latest server results and limitations are in [docs/ACCEPTANCE_2026-09-30.md](docs/ACCEPTANCE_2026-09-30.md); earlier evidence is in [docs/ACCEPTANCE_2026-09-26.md](docs/ACCEPTANCE_2026-09-26.md).

## End-of-day handoff and next actions

- **30 September gateway update:** the application stack now publishes only
  HTTPS port **3000**. Gitea is at `/`, findings at `/dashboard/`, Jenkins at
  `/jenkins/`, Grafana at `/grafana/`, and Prometheus at `/prometheus/`.
  Dashboard, Jenkins and Prometheus require the generated gateway login;
  Grafana and Gitea retain their own accounts. Host SSH remains separate.
  Kali verified closed old ports, all 32 Grafana query results, the Live
  WebSocket, eight healthy targets, HTTPS Git access and authenticated audit
  and triage exports. Jenkins #340 / scan #264 completed on `f76980f` through
  the updated webhook; a real HTTPS Git push of the Jenkins authentication
  fix `49ee067` also triggered successful Jenkins #341.
  See [Gateway setup](docs/GATEWAY.md) for the CA, credentials and recovery.
  The pre-change backup is `~/secureguard-backups/pre-proxy-20260930-145430`;
  new gateway keys/configuration are privately backed up under
  `~/secureguard-backups/gateway-20260930` on Kali.
- **30 September monitoring update:** GitHub, Gitea, and Kali reached
  `a849b8e` before this documentation update. The private pre-change backup is
  `~/secureguard-backups/pre-grafana-20260930-115649` on Kali. It contains a
  PostgreSQL dump, Grafana/Prometheus archives, Compose/private configuration,
  Wazuh alerts, and Wazuh API configuration; all seven checksum entries passed.
  This is a verified backup, not a full restore drill. The Grafana dashboard
  now loads updated queries; all eight Prometheus targets are up, CPU/memory
  and container panels return data, the CVE endpoint and Wazuh SCA endpoint
  return HTTP 200, and Loki has recent Wazuh alerts. Falco remains stopped
  because its kernel driver is unsupported in this Kali lab; its panel
  correctly shows zero. Recheck after the final documentation commit.
- Jenkins **#322** succeeded and scan **#248** completed with 3,742 stored
  findings and all required reports accepted, including Dependency-Check and
  Checkov SARIF. AI PR #18 published 220 numbered conversation parts covering
  each of the 3,742 findings exactly once. Its proposed fixes failed a targeted
  Bandit rescan, so do **not** merge that PR.
- All 13 current Gitea repositories were triggered through their push hooks.
  The 30 September coverage audit found seven latest scan records in
  `complete`, five in `failed`, and `Range` at `pr_opened` (a completed scan
  whose AI workflow changed its status). Investigate the five failures before
  checking off repository coverage: Moondream, Netflix-Hystrix, Netflix-zuul,
  browser-use, and sietlms-moodle-.
- The Kali server is reachable at its new address. On 30 September, GitHub `main`, Gitea `main`, and the Kali checkout matched at `ef9d6cbf9b2196e926f625d9f36de95e5658dcb5`. Recheck parity after the next documentation/code push.
- Jenkins **#315** failed because Dependency-Check could not produce a valid report. **#316** hit the 120-minute pipeline timeout while filling the NVD cache; its scan **#242** was reconciled to `failed`. Commit `ef9d6cb` adds an aborted-build handler so future timeouts mark their scans failed.
- Jenkins **#317** / scan **#243** failed after reaching 110,000 of 399,513 NVD records. Dependency-Check reported repeated NVD request failures and DNS lookup errors for CISA and RetireJS; no valid Dependency-Check SARIF or accepted report set was uploaded. The next DNS-configured scan must still pass the full report contract.
- On 30 September, the current server commit passed Compose validation, service/Jenkins image builds, and all 29 Python tests; orchestrator, CVE, dashboard, and Jenkins endpoints returned HTTP 200. The private coverage audit found 13 repositories with active push hooks but no fresh complete coverage across all 13. Two ancient `running` records, scans #185 and #222, were verified stale and marked `failed`.
- Jenkins **#320** filled the NVD cache from the official Dependency-Check datafeed, then failed at SARIF report generation. The root-owned report directory was not writable by the UID-1000 scanner; the next commit grants that scanner write access and needs a fresh run.
- Jenkins **#321** generated a 170,250-byte Dependency-Check SARIF report, confirming the cache and write fix. Report validation then rejected `checkov.sarif` because the pipeline had captured Checkov console output instead of its native SARIF file. The next commit corrects that output path; uploads remain unverified.
- **Next in order:** diagnose and rerun the five failed repository scans, review or reject AI PR #18, triage current high findings, and perform a separate restore drill for the new backup. Recheck Grafana and commit parity after each deployment.
- The 50 older open AI PRs have no numbered finding comments. The user chose the detailed whole-scan conversation format for **future PRs only**; leave those older conversations unchanged. They still require ordinary review before any merge.
- Do not run builds or tests on the laptop. Make code changes here, push GitHub, update the Kali checkout, push Gitea from Kali, and test there. Keep credentials and raw findings off Git.

## Working and verified

- [x] Consolidate Compose port bindings behind the HTTPS gateway on 3000;
  anonymous dashboard/Jenkins/Prometheus requests return 401, the public
  Jenkins webhook returns 404, and internal Gitea delivery still works.
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

- [x] Verify Dependency-Check SARIF and upload on the server. Jenkins #322 generated valid SARIF and uploaded the required report set; scan #248 completed.
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
- [ ] Investigate old latest scan states: `Netflix-zuul`, `sietlms-moodle-`, `Portfolio`, and `browser-use` show `failed`. The stale `Portfolio` and `browser-use` records were reconciled on 30 September; all four still need fresh terminal scans.
- [ ] Reconcile the scan inventory with Gitea: scan history includes `ShadowPatch`, while the current Gitea list includes `SIET-Hackathon`. Confirm which repositories are in scope.
- [ ] Document that the shared Jenkinsfile and Semgrep rules come from `VigilentOps/main`. Other repositories' own Jenkinsfile/scanner files are older or absent; update those files only if they must run independently of the shared job.

### 4. Validate AI remediation safely

- [x] Prepare bounded 429/temporary-error handling, a single-worker lab default, exact scan-commit checks, better finding context, and model-output gates. See [AI rate limits and patch quality](docs/AI_RATE_LIMITS_AND_QUALITY.md).
- [x] The 29 server Python tests included simulated 429 deferral, invalid model-output fallback, finding-comment splitting, credential redaction, and partial comment-post failure.
- [x] Audit existing AI PR conversations: 50 older open PRs have no numbered finding comments. The user chose to apply the complete conversation requirement to future PRs only.
- [ ] On the server, verify a controlled 429/deferred task and invalid-output fallback; confirm final failures leave findings open and show a clear diagnostic.
- [ ] Select a real open Python SAST finding and verify that the worker creates a `WIP:` Gitea PR against the correct repository and base commit, without exposing secrets.
- [x] On server-created PR #18, verify its conversation contains every numbered finding part for **all** scanner tools in scan #248: 220 parts covered all 3,742 database findings once each. No historical Grafana password was present; partial-comment failure remains covered by the server Python suite.
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
- [ ] Configure Jenkins's own user accounts and role permissions before
  multi-user or production exposure. Its stored security realm/strategy were
  `None`/`Unsecured`; the new gateway now requires authentication for every
  public Jenkins route. Review the trusted Docker network separately.
- [ ] Back up and test restore of PostgreSQL and persistent Gitea/Jenkins/Grafana volumes. Document recovery steps and retention.
- [ ] Pin and maintain scanner/container versions, define update cadence, and establish a monitored vulnerability exception process.
- [ ] Define ownership, alert routing, and response procedures for failed scans, unavailable services, new high findings, and AI PR review.

**Completion rule:** a green Jenkins build by itself is insufficient. The lab is complete when the required sections above have evidence, remaining findings have an explicit decision, and the final run succeeds on the exact release commit.
