# Project completion checklist

Status: **code prepared; lab acceptance incomplete**, 30 September 2026.
This is a self-hosted lab reference implementation. The server is currently
unavailable. Edit/push on the laptop; run all builds, tests and live checks on
Kali. Follow [Next server session](docs/NEXT_SERVER_SESSION.md).

## Evidence and handoff

- The application stack publishes only HTTPS **3000**. Routes: Gitea `/`,
  findings `/dashboard/`, Jenkins `/jenkins/`, Grafana `/grafana/`, Prometheus
  `/prometheus/`. Host SSH is separate. Current gateway username: `BeyondBug`.
  Passwords and private keys stay off Git.
- Prior gateway acceptance: eight healthy Prometheus targets, all 32 Grafana
  query results, Live WebSocket, HTTPS Git and end-to-end Jenkins #340/#341.
  See [30 September evidence](docs/ACCEPTANCE_2026-09-30.md).
- Last confirmed deployed code: `7bcfd0c` on Kali and Gitea. Compose validation
  and **33 Python tests passed on Kali at that commit**. The subsequent code
  changes and expanded tests have not run. Recheck GitHub/Gitea/server parity.
- Private backups: `~/secureguard-backups/pre-grafana-20260930-115649`,
  `~/secureguard-backups/pre-proxy-20260930-145430`, and
  `~/secureguard-backups/gateway-20260930`. Integrity passed; these newer
  snapshots have not completed a full service recovery rehearsal.
- Latest known repository failures: Moondream, Netflix-Hystrix, Netflix-zuul,
  browser-use and sietlms-moodle-. A hook exists for all 13 current Gitea repos;
  this does not establish current successful coverage. The interrupted rerun
  may have queued some builds; inspect the server queue before retrying.
- AI PR #18 covered all 3,742 scan #248 findings in 220 numbered parts, but
  original Bandit B107/B310 findings survived the targeted rescan. **Do not
  merge it unchanged.** The user chose complete conversations for future PRs
  only; leave the 50 older conversations unchanged.

## 1. Scanner execution and trustworthy coverage

- [x] Add explicit OSV exit-128 `not_applicable` coverage; reject other execution
  errors and require native output for exit 0/1.
- [x] Increase bounded Trivy source/image timeouts; fail image scanner errors.
- [x] Exclude only Moodle's malformed/encrypted ZIP test fixtures from
  Dependency-Check; retain other source/dependency/archive coverage.
- [x] Prepare server-side report receipts, required-report completion gates,
  idempotent identical uploads and rejection of conflicting uploads.
- [x] Preserve available package, installed/fixed version and image metadata;
  retain critical severity and advisory IDs from native scanner formats.
- [x] Record the shared pipeline commit; prepare an audit against each default
  branch's current head. Retire the obsolete permissive alternate pipeline.
- [ ] Deploy migrations 002/003 and rebuild/restart the changed services on Kali.
- [ ] Verify malformed/missing reports and failed uploads fail the build/API;
  optional coverage is explicit; each native report maps correctly.
- [ ] Verify temporary NVD key cleanup and rejection of untrusted clone URLs.
- [ ] Rerun the five failed targets successfully with the current pipeline.
- [ ] Verify fresh scans and delivered push hooks for every intended repository;
  record branch, target commit, pipeline commit, build ID, scan ID and result.
- [ ] Reconcile historical ShadowPatch versus current SIET-Hackathon scope.
  Shared rules come from VigilentOps/main; target-owned Jenkinsfiles need
  updating only when those repositories must run independently.

## 2. AI patch quality and failure handling

- [x] Prepare bounded provider retries/deferred Celery work and single-worker
  defaults, output gates and exact scan-commit checks.
- [x] Add Python interface preservation and a Bandit before/after gate that
  ignores suppression comments and rejects remaining target rules or increased
  medium/high findings. Rejection feeds the next configured model.
- [x] Use the scanned base branch, restrict repository origins and keep Git
  tokens in temporary askpass/environment rather than command arguments.
- [x] Keep findings open if whole-scan conversation publication is incomplete;
  include report coverage and available artifact metadata in future PRs.
- [x] Prepare administrator-only PR-head scanning without queuing another AI fix.
- [x] Prepare a server-only controlled Celery/HTTP retry and fallback fixture.
- [ ] Run the expanded Python suite and controlled failure fixture on Kali.
- [ ] Review/correct or explicitly reject PR #18; generate one fresh real PR.
- [ ] Verify correct repository/base/head and every promised numbered part;
  review the whole diff and changed interfaces through real clients.
- [ ] Scan the exact PR head; confirm the original issue disappears and no
  material regression occurs. Approve or reject explicitly; no automatic merge.
- [ ] Verify real task diagnostics and finding states after terminal provider
  failure, malformed output and unsafe/irrelevant proposals.

## 3. Findings and release decisions

- [x] Prepare private artifact-aware exports and a triage completeness checker.
- [x] Define dispositions and lab release threshold in
  [Finding triage](docs/FINDING_TRIAGE.md).
- [ ] Export a fresh complete scan and manually verify grouping by advisory,
  package/version/image/path. Historical metadata blanks need manual review.
- [ ] Resolve or explicitly disposition every critical/high/secret finding;
  prioritize deployed images and reachable runtime dependencies.
- [ ] Review the Python SAST findings; apply supported dependency/base-image
  upgrades, rebuild and rescan before recording a fix.
- [ ] Record accepted exceptions with impact, mitigation, named owner, evidence
  and review date. Assign plans/owners to remaining medium/low findings.
- [ ] Run the completeness checker and review its evidence. A passing CSV
  check does not establish exploitability or authorize risk acceptance.

## 4. Access controls and monitoring

- [x] Publish only gateway port 3000; protect public management paths and block
  public Jenkins trigger requests. Previously verified on Kali.
- [x] Prepare native Jenkins accounts, administrator/metrics permissions and
  CSRF; private bootstrap credentials and authenticated Prometheus scraping.
- [x] Replace the literal trigger token in code with a Jenkins credential;
  prepare private hook migration and test-delivery tooling.
- [ ] Back up, deploy Jenkins security, initialize the updated job trigger,
  then migrate all hooks in the documented order.
- [ ] Verify native anonymous access denied, metrics privileges limited, admin
  login/CSRF functional and old webhook token rejected without starting work.
- [ ] Recheck all Grafana panels, eight targets, WebSocket and HTTPS Git after
  deployment. Credentials must not appear in logs or public PR comments.
- [x] Correct the inspected Falco `nodriver` configuration to modern eBPF.
- [ ] Verify Falco remains running and captures a controlled event through its
  exporter and Grafana. Startup/capture has not been established; BTF exists
  on this Kali host, but kernel/permission compatibility needs a live check.

## 5. Backup, recovery and final acceptance

- [x] Prepare private consistent backup automation and a disposable database/
  volume restore drill with checksum, row-count and content comparison.
- [ ] Run a new backup and isolated restore drill on Kali; retain older backups
  and the recorded image IDs. Confirm live services restart after the backup.
- [ ] Rehearse full restored service access in an isolated stack. Archive
  comparison alone does not prove Gitea/Jenkins/Grafana recovery.
- [x] Update deployment, architecture, testing, operations and server handoff
  documentation to describe the prepared code and pending checks.
- [ ] Run Compose validation, builds, migrations, the expanded Python suite and
  health/client checks on the exact final commit.
- [ ] Complete one real push → Jenkins → reports → database → dashboard run and
  one reviewed AI PR-head run; record results in a dated acceptance report.
- [ ] Confirm exact GitHub/Gitea/Kali commit parity after the final push.
- [ ] Check every required pending item with evidence before declaring the lab
  complete.

## Additional gates before production exposure

- [ ] Rotate historically exposed Grafana/gateway passwords, NVD/API/webhook
  credentials as applicable; review access to old logs and Git history.
- [ ] Review Docker socket access, privileged services, internal-network trust,
  host firewall and external Wazuh agent access.
- [ ] Pin and maintain all scanner/container/plugin versions after server
  compatibility checks; several scanner tags remain mutable.
- [ ] Assign operational owners, alert routing, response procedures, backup
  retention/off-host copies and a monitored exception review process.
- [ ] Replace lab-only TLS/access assumptions with controls appropriate to the
  intended deployment. Native Jenkins security code still needs live evidence.

**Completion rule:** a green build is insufficient. All required gates need
server evidence, findings need explicit reviewed decisions, and the final run
must succeed on the exact release commit. Offline code preparation cannot
complete those checks.
