# Project completion checklist

Status: **deployed lab; release acceptance incomplete**, 1 October 2026.
Builds, tests, scanners and browser checks run on Kali at `10.20.29.248`.
No application or test runs are performed on the laptop. See
[today's evidence](docs/ACCEPTANCE_2026-10-01.md) and
[deployment procedure](docs/NEXT_SERVER_SESSION.md).

## Current handoff

- HTTPS **3000** is the only published application port. Gitea `/`, findings
  `/dashboard/`, Jenkins `/jenkins/`, Grafana `/grafana/`, Prometheus
  `/prometheus/`. Host SSH is separate. Username: `BeyondBug`; credentials
  and private configuration stay off Git.
- Native Jenkins authentication, matrix permissions, CSRF and private hooks
  are deployed. All eight Prometheus targets and 22 provisioned Grafana
  queries passed. Grafana Live returned 101. Falco now captures real events.
- Jenkins was upgraded from 2.555.3 to pinned **2.580.1 LTS / Java 25**;
  all 97 managed plugins loaded and no installed-version advisory warning
  remained in the official update-center check. Jenkins #395 / scan #306
  completed on the new controller. The subsequent image removes its unused
  SSH client; Git remains available. See [upgrade procedure](docs/JENKINS_UPGRADES.md).
  That cleaned image subsequently passed Jenkins **#396 / scan #307** at
  `3bae893`; all 13 report receipts were stored. Its separate Trivy image
  audit reported zero critical and 92 high records requiring review.
- The gateway now uses pinned Nginx **1.30.5**. TLS, HTTPS Git, Grafana Live,
  authenticated routes, eight targets and 22 queries passed after recreation.
  Only running gateway port 3000 is published; 17 former listeners were closed.
- All 13 current repositories passed default-branch head coverage using shared
  pipeline `83b5434` (Jenkins #379–391 / scans #289–301). Later changes must
  retain their own exact-commit evidence.
  Every current repository is a real project requiring remediation review;
  none has been classified as intentionally vulnerable.
  The owner confirmed the target repositories are currently used for testing;
  no target application deployment was identified in this session.
- Jenkins #346 / scan #268 accepted 13 reports with 3,820 finding records.
  The later #364 / scan #286 reported zero critical and 54 high across
  285 records. Those counts are historical scan records,
  not a unique vulnerability count or a release disposition.
- The dashboard now polls summaries and fetches 50 findings per page;
  browser checks verified all tabs, page navigation and filtered search.
  The expanded suite passed **96 tests** at `ab6c0b0` on Kali.
- Private backup `~/secureguard-backups/lab-20261001-114129` passed an isolated
  restore: 123 table counts and eight volume archives matched, followed by
  authenticated restored Gitea/Jenkins/Grafana access. Writers/workers resumed;
  older snapshots are retained. Full restored application workflows remain
  beyond this core access drill.
- AI proposals require manual approval. PR #18 and the original sg-bench
  proposal were rejected; 21 proposed finding records were reopened.
  PR #1 was corrected to retain only the reviewed SQL parameterization and
  merged after SQLite behavior checks and Jenkins #392 / scan #302 on its
  exact head. Other findings remain open. This was an AI-assisted fix with
  manual correction, not evidence of fully automated remediation.
- The user chose complete finding conversations for future PRs only. Leave
  the 50 older conversations unchanged; they still require normal review.

## 1. Scanner execution and trustworthy coverage

- [x] Select versioned scanner images, pull all 11 selected images on Kali
  and record private image/digest inventory.
- [x] Deploy migrations 002/003 for artifact metadata, report receipts and
  pipeline commit tracking.
- [x] Finalize accepted reports before enrichment/AI; reject incomplete
  completion and later attempts to overwrite accepted scans as failed.
- [x] Validate native reports, identical-upload idempotency and conflicting
  upload rejection in the server suite. Live malformed report returned 422.
- [x] Preserve available severity/advisory/package/version/image metadata;
  OSV artifact metadata extraction has regression coverage.
- [x] Add Hadolint/ShellCheck and explicit no-file receipts; #346 accepted
  both reports. OSV unsupported input requires its documented exit 128.
- [x] Clean target checkouts and verify the Docker host mount's target commit.
- [x] Restrict clone origins/paths; live untrusted origin and bad SHA returned
  422. Temporary NVD properties cleanup is implemented before archival.
- [x] Preserve scanner reports and execution diagnostics in authenticated
  Jenkins artifacts before workspace cleanup; exclude temporary NVD secrets.
- [x] Repair Moodle's precise ZIP fixture exclusion and sg-bench's Python
  indentation error. #361 / scan #283 and #362 / scan #284 completed.
- [x] Rerun the five previously failed targets successfully; audit all 13
  default-branch heads. Record the mixed pipeline revisions in evidence.
- [x] Reconcile scope: ShadowPatch is historical; SIET-Hackathon is a current
  scanned target. Shared pipeline/rules come from VigilentOps/main.
- [x] Audit all 13 target heads against shared pipeline `83b5434`, recording
  target SHA, pipeline SHA, build and scan. Recheck changed targets after
  later commits; do not describe this as coverage of a newer pipeline SHA.
- [x] Observe NVD key removal after Dependency-Check in Jenkins #395, while
  its SARIF still exists. A temporary Jenkins job's real malformed upload
  returned 422, failed build 1 and scan #304, and stored zero findings/reports;
  the fixture job was removed.
- [x] Audit all 25 exact images referenced by existing Compose containers,
  including stopped services, using Trivy and Dockle. Keep the full private
  reports and database timestamp. Audit changed Jenkins/gateway images
  separately; valid reports do not dispose of their remaining findings.
- [ ] Extend image coverage beyond the first Dockerfile when repositories
  deploy multiple images; inventory intended artifacts before accepting scope.

## 2. AI patch quality and failure handling

- [x] Bound provider retries, cooldowns, route budgets, Celery deferral and
  single-worker defaults. Worker prefetch is one task per execution slot.
- [x] Verify controlled RETRY then FAILURE, malformed-output rejection and
  validated fallback on Kali without real PR/database mutations.
- [x] Verify synthetic model compatibility for three configured routes;
  record other routes' observed 429/timeout instead of assuming compatibility.
- [x] Require exact scan commit, trusted clone origin, private Git askpass,
  valid UTF-8, safe paths and preservation of public Python interfaces.
- [x] Compare original/candidate Bandit results with suppression disabled;
  reject remaining target rules or additional medium/high issues.
- [x] Preserve validated earlier file proposals when a later file defers;
  leave deferred findings open and label the PR as partial/unverified.
- [x] Reject observed pickle-to-JSON migrations and fast password-digest
  substitutions; regression tests passed. These checks are deliberately
  bounded and do not prove arbitrary runtime/security correctness.
- [x] Prepare administrator-only exact PR-head scans without another AI task.
- [x] Generate a real WIP proposal: sg-bench PR #1 from scan #283, base
  `85dffdf`, head `cbf9695`; Jenkins #363 scanned that head successfully.
- [x] Record final review decisions for PR #18 and sg-bench PR #1; keep
  rejected proposal findings open and retain the review evidence.
- [x] Verify the new PR #1's 11 numbered parts cover all 179 stored findings
  exactly once. PR #18's earlier 220-part verification remains recorded.
- [x] Review the accepted SQL patch's entire diff and exercise its SQLite
  caller with normal IDs and injection attempts; preserve surrounding code.
- [x] Produce one accepted AI-assisted fix with manual correction, a reviewed
  diff, exact PR-head rescan and behavior checks. PR #1 head `652da8b` passed
  Jenkins #392 / scan #302, then merged as `bbbb52f`. Other findings stay open.
- [ ] Review live terminal task diagnostics and finding states after exhausted
  providers or unsafe proposals. Multi-worker/global quota coordination and
  duplicate task admission need additional design before scaling.

## 3. Findings and release decisions

- [x] Export scan #268 privately; provide artifact-aware grouping and a triage
  completeness checker. Define [release thresholds](docs/FINDING_TRIAGE.md).
- [x] Apply supported AnyIO/web dependency upgrades, remove unused CVE build
  packages, refresh Debian runtime packages and replace CRA with Vite/Node 24.
  Server builds and 96 tests passed; Vite lock generation reported zero npm
  audit vulnerabilities. A fresh full scan is still required.
- [x] Complete #364 / scan #286 after those changes: zero critical, 54 high.
  This result covers the existing pipeline scope, including one built image.
- [x] Verify final container hardening: remove unused runtime/bootstrap tools,
  image health checks, unprivileged dashboard Nginx and limited workflow
  permissions. Rebuild, verify clients and inspect fresh scanner results.
- [x] Complete the post-upgrade server checkpoint at `3bae893`: Compose
  validation, changed-service/Jenkins builds, migrations, 96 tests, real
  HTTPS push and complete scan #307. This is an operational checkpoint;
  security dispositions and the release decision remain open below.
- [x] Export all 13 current default-head scans after the Jenkins upgrade to
  private `reports/triage/heads-after-jenkins-upgrade-20261001`: 130 critical
  and 2,215 high records still need review; the completeness checker fails.
- [ ] Review grouping by advisory,
  package/version/image/path, including historical metadata gaps.
- [ ] Resolve or explicitly disposition every critical/high/secret finding
  across intended repositories and deployed images; review reachability.
- [ ] Review Python SAST findings and rescan any repaired branch before
  marking a finding fixed.
- [ ] Record exceptions with impact, mitigation, a real named owner, evidence
  and review date; assign plans/owners for remaining medium/low findings.
- [ ] Run the completeness checker. A populated CSV does not authorize risk
  acceptance or establish exploitability.

## 4. Access controls and monitoring

- [x] Publish only application port 3000; protect public management paths and
  block public Jenkins triggers. All 16 former application listeners closed.
- [x] Deploy native Jenkins user realm, matrix permissions and CSRF; anonymous
  Docker-network API access denied, metrics account cannot administer Jenkins.
- [x] Upgrade Jenkins core, Java and compatible plugins after an isolated
  restored-volume rehearsal and private pre-upgrade backup. Verify plugin
  activation, advisories, native access and a successful real push/scan.
- [x] Migrate all 13 hooks to private credentials; historical token rejected
  and private dry-run matched exactly one job without queuing work.
- [x] Verify all eight targets, 22 provisioned Grafana queries, Live WebSocket,
  authenticated dashboard/API and HTTPS Git after gateway deployment.
- [x] Deploy Falco 0.43.0/container plugin with modern eBPF; capture a controlled
  event and verify exporter/Prometheus rule data. Container liveness remains
  distinct from event capture.
- [x] Refresh dashboard upstream DNS after container recreation; test summary
  polling, paged findings, filters and all dashboard tabs in a Kali browser.
- [ ] Rotate historical credentials with their providers/owners and review old
  logs/history. Do not publish replacement values or claim unperformed rotations.

## 5. Backup, recovery and final acceptance

- [x] Create a private consistent snapshot, retaining exact runtime image IDs.
- [x] Restore the database and eight volume archives into disposable resources;
  compare all 122 table counts and archive contents; remove drill resources.
- [x] Rehearse restored Gitea/Jenkins/Grafana access in an isolated stack;
  verify native authentication, recovered inventory and disabled execution.
  Full restored application workflows are a separate future exercise.
- [x] Take a fresh snapshot covering the deployed native access configuration;
  retain older snapshots and verify writers resume normally. Snapshot
  `lab-20261001-114129` records checkout `572cfc4` and exact runtime image IDs.
- [x] Retain Jenkins pre-upgrade volume/configuration backup
  `~/secureguard-backups/pre-jenkins-upgrade-20261001-121746` and its old image.
  Rehearse the upgraded core with snapshot credentials/security startup and
  execution disabled. Preserve the old gateway image for gateway rollback.
- [ ] Run Compose validation, builds, migrations, suite and health/client checks
  on the exact final release commit.
- [ ] Complete final push → Jenkins → reports → database → dashboard acceptance
  and one accepted AI PR-head review; record redacted results.
- [ ] Confirm exact GitHub/Gitea/Kali commit parity after the final push.
- [ ] Update documentation/checklist with final evidence and check every
  required remaining gate before declaring the lab complete.

## Additional gates before production exposure

- [ ] Review Docker socket/privileged services, internal-network trust, host
  firewall and external Wazuh agent access for the intended environment.
- [ ] Maintain immutable image/plugin versions; current version tags may be
  mutable. Falco's current exporter needs a replacement transport before 0.44.
- [ ] Assign real operational owners, alert routes, response procedures, backup
  retention/off-host copies and an exception review schedule.
- [ ] Replace lab TLS/access assumptions with deployment-appropriate controls.

**Completion rule:** passing builds and completed scans do not resolve findings.
The lab needs explicit reviewed dispositions, a validated real fix, recovery
evidence and a successful acceptance run on the exact release commit.
