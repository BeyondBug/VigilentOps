# Server acceptance progress — 1 October 2026

This is a chronological progress record, beginning with the initial inspection
and ending with the later verified results below. Release acceptance remains
incomplete. Builds and tests run only on Kali; results apply to their recorded
commits and scope.

| Check | Evidence | Result |
| --- | --- | --- |
| SSH and repository inspection | Previously verified SSH host key at `10.20.29.248`; branch `Features`, clean tracked checkout at `7bcfd0c6412535d8ac5b5a540c0b973a1aff785b` | Pass before deployment |
| Initial service inspection | Core services running; Falco and its exporter restarting | Runtime monitoring needs repair |
| New code acceptance | Pending server backup, image builds, expanded suite, migrations and live checks | Not established |

## First regression run

Kali pulled `bed4d02` and built dashboard, migration, orchestrator, worker,
CVE, Wazuh proxy and Jenkins images. Compose configuration validation passed.
The expanded suite found an unmatched parenthesis in the SARIF description
expression, preventing API import. Deployment stopped before recreating
services. Correction `9e3dfff` was pushed and pulled; **all 90 Python tests
passed on Kali** using the new image with the exact corrected checkout mounted
read-only. Rebuild the corrected application image before deployment.

Private Jenkins bootstrap files were prepared without printing credentials.
The backup helper refused to interrupt an active CVE enrichment task; no
consistent new backup has completed yet. Scanner image availability/digest
preflight is underway and does not establish report compatibility.

Falco 0.39.2's diagnostic run reproduced a `sys_exit` BPF load failure with
errno 22 and an invalid `outputs` configuration property. Its exporter loses
the gRPC stream when Falco exits. An upgrade requires both actual event capture
and exporter verification; it is not accepted merely because an image pulls.

## Further pre-deployment checks

- Jenkins's live declarative parser accepted the updated Jenkinsfile.
- The isolated Celery fixture passed 429 RETRY then bounded FAILURE, malformed
  output rejection and fallback to a Bandit-validated candidate. No provider
  request, real PR or finding-state write was made by that fixture.
- All 11 selected scanner images pulled and their local IDs/registry digests
  were recorded privately in `reports/scanner-images-20261001.json`.
- Falco 0.43.0 initialized with the container plugin and corrected schema,
  exiting successfully after a short diagnostic. Its summary reported zero
  captured events, so this is not event or exporter acceptance.

The selected [Falco 0.43.0 release](https://github.com/falcosecurity/falco/releases/tag/0.43.0)
retains deprecated gRPC for this exporter. Falco 0.44 removes gRPC, so upgrading
beyond this version needs a replacement event transport first; see the
[0.44 release notes](https://github.com/falcosecurity/falco/releases/tag/0.44.0).

- A longer isolated Falco check captured two actual opens of the dedicated
  `/tmp/secureguard-falco-check` file. This confirms modern eBPF capture;
  deployed exporter/Prometheus acceptance remains separate.
- Native Hadolint and ShellCheck scans of the Kali checkout produced valid
  adapter reports: five Dockerfiles/14 records and one shell file/one record.
- The configured model fixture passed for `openai/gpt-oss-20b`,
  `poolside/laguna-xs-2.1` and `nvidia/nemotron-3-ultra-550b-a55b`.
  `gemini-3.6-flash` returned HTTP 429; `google/gemma-4-31b-it` timed out.
  These are observed route outcomes, not evidence that the failed models are
  permanently incompatible or that a passed model fixes arbitrary findings.
  An initial report permission error was corrected; the final private report
  records the completed bounded rerun. The fixture now checks output access
  before sending requests.

The first full backup run failed at a root-owned archive permission step;
its cleanup restarted services. Correction `ef96a71` precreates archives
with operator ownership. The subsequent consistent backup completed at
`~/secureguard-backups/lab-20261001-091137` with eight volume archives and a
database dump. Restore verification remains pending. The failed earlier
snapshot is not accepted recovery evidence.

Prepared changes include scanner version selection and digest inventory,
report completion before AI, receipt coverage in scan details, generic API
failures, and notification delivery outcomes without raw source/descriptions.
AI source resolution rejects symlinks and `.git` metadata; write validation
preserves UTF-8 and the guarded interfaces. Model compatibility and real fix
quality still require separate checks. See [Next server session](NEXT_SERVER_SESSION.md).

Do not merge PR #18 unchanged or mark the lab complete until repository
coverage, finding dispositions, reviewed AI fixes, recovery and exact commit
parity have evidence. Credentials and raw logs remain private.

## Deployed checks and fresh scans

The corrected images were rebuilt, migrations 002/003 exited successfully,
and the CI/monitoring stack was recreated. Native Jenkins now uses its private
user realm, matrix permissions and CSRF protection. Direct Docker-network
checks returned 403 for anonymous API access, 200 for the administrator and
metrics scrape, and 403 when the metrics account attempted administration.
All 13 hooks were migrated to the private credential. A dry run rejected the
historical token with 404 and matched exactly one job with the new token;
neither request queued work.

Gateway recreation was required to replace a stale individual configuration
bind mount after Git replaced its inode. The authenticated monitoring checker
then passed all 22 provisioned queries with nonempty data frames and no
datasource errors; all eight Prometheus targets were up. Grafana Live returned
101. Docker inspection found only gateway port 3000 published, and TCP checks
found all 16 former application listeners closed.

Falco 0.43.0 and its exporter remain running. A harmless shell invocation in
the dashboard container generated the custom shell rule; the Prometheus
`falco_events` query returned that rule and five other rule series. This
replaces the earlier unsupported-driver limitation with live event evidence.

The new backup at `~/secureguard-backups/lab-20261001-091137` passed an isolated
restore: 122 database table counts matched and all eight restored volumes
matched their archives. Disposable resources were removed. This does not
establish restored service login/access; that broader drill remains open.

Jenkins #344/#345 exposed sandbox restrictions on dynamic environment writes
and direct Groovy JSON serialization. The pipeline uses supported environment
assignment and `writeJSON` steps. At `afbda39`, real Gitea push build **#346**
finished SUCCESS; scan **#268** completed with **3,820 findings** and 13 accepted
report receipts, including Hadolint/ShellCheck. Severity records: six critical,
314 high, 2,382 medium, 1,105 low, 11 informational and two unknown. These
records are not dispositions or a count of distinct vulnerabilities. The
private triage export is `reports/triage/scan-268`.

All 13 repository reruns were queued through Gitea test deliveries. Early
results include successful current scans of Acdemy, Moondream,
Netflix-Hystrix, Netflix-zuul, Portfolio, Range, SIET-Hackathon and SIET-WEBSITE.
The full terminal coverage audit remains pending.

The real scan #268 AI task entered RETRY after provider deferral; no accepted
real PR fix has been established. Three configured routes passed synthetic
compatibility, which does not guarantee availability on a larger real file.

## Next security corrections

Scan #268 reports AnyIO 4.9.0 in the two Python requirement sets. The
[reviewed AnyIO advisory](https://github.com/advisories/GHSA-82r6-8w77-94w6)
identifies 4.14.2 as patched for CVE-2026-63374. Code now pins that version
for the API, CVE service and Wazuh proxy; rebuild and rescan are required.
The CVE Dockerfile no longer installs unused GCC/libpq development packages
and requires binary wheels. OSV artifact package/version extraction and
partial AI proposal handling are prepared with regression checks. These
latest corrections have not yet passed the server suite or deployment.

## Later results: coverage, dependencies, dashboard and AI review

The changes described as pending above were subsequently built and deployed.
They remain chronological observations; they do not establish final release
acceptance.

| Check | Evidence | Result |
| --- | --- | --- |
| Service dependency upgrades | AnyIO 4.14.2, refreshed FastAPI/Uvicorn/HTTPX, API Pydantic/instrumentation and Debian runtime upgrades built on Kali; unused CVE GCC/libpq development packages removed | Builds and 92-test suite passed before the dashboard changes |
| Dashboard build chain | Vite 8.3.1, React plugin 6.1.1, Node 24; lock generated on Kali | Build passed after correcting `theme.jsx`; lock generation reported zero npm audit vulnerabilities |
| Summary and finding pages | `a9807a7`, summary aggregation and paged `/api/findings` filters | Builds and 94 tests passed; live response embedded zero findings in the scan summary and returned 50 of 104,235 recent-scope finding records |
| Browser rendering | Kali Chromium/Playwright, isolated temporary NSS trust store importing only the lab CA | All four tabs, next-page navigation, literal search and scan receipt details passed; zero JavaScript errors or failed dashboard requests; TLS verification enabled |
| Latest AI contract gates | `ab6c0b0`, reject pickle-to-JSON and fast password-digest substitutions, including import aliases | Builds and 96 tests passed; worker recreated with the new code and retained queue |
| Live negative API checks | Untrusted repository origin/bad SHA/malformed report 422; failed-scan completion/fix and late failure of accepted scan 409 | Existing scan states/findings/receipts remained unchanged |
| Monitoring after dashboard update | Private `reports/gateway-monitoring-paged.json` | Eight targets up; all 22 provisioned Grafana queries returned nonempty frames without datasource errors |

### Repository coverage

The private audit `reports/coverage-20261001.md` found current default-branch
head coverage for all 13 repositories. These runs used **two** pipeline
revisions, not one final release revision.

| Repository | Jenkins build | Scan | Result | Shared pipeline |
| --- | ---: | ---: | --- | --- |
| Acdemy | 347 | 269 | complete | `afbda39` |
| Moondream | 348 | 270 | complete | `afbda39` |
| Netflix-Hystrix | 349 | 271 | complete | `afbda39` |
| Netflix-zuul | 350 | 272 | complete | `afbda39` |
| Portfolio | 351 | 273 | complete | `afbda39` |
| Range | 352 | 274 | complete | `afbda39` |
| SIET-Hackathon | 353 | 275 | complete | `afbda39` |
| SIET-WEBSITE | 354 | 276 | complete | `afbda39` |
| bagisto | 356 | 278 | complete | `afbda39` |
| browser-use | 357 | 279 | complete | `afbda39` |
| VigilentOps | 360 | 282 | complete | `75e6986` |
| sg-bench | 361 | 283 | complete; AI proposal subsequently rejected | `75e6986` |
| sietlms-moodle- | 362 | 284 | complete | `75e6986` |

The initial sg-bench run #358 failed on Python indentation; Moodle #359
failed on malformed/encrypted ZIP fixture processing. Those failures were
retained. The sg-bench repair `85dffdfb59c2aba2d32d3a5e97555f5278ca8f6c`
only dedented the invalid top-level Python definitions, preserving source
values/logic; it does not remediate its security findings. Moodle's exclusion
matches only `lib/filestorage/tests/fixtures/*.zip` through the scanner's Ant
pattern. The fresh reruns succeeded without suppressing general scanner
execution errors.

All current repositories are real projects according to the user; none is
accepted as an intentionally vulnerable exception. Historical ShadowPatch is
absent from current Gitea inventory; SIET-Hackathon is present and scanned.
Shared rules/pipeline remain central in VigilentOps/main.

Scan #282 after initial dependency/image corrections reported **three critical
and 175 high records**, down from #268's six critical/314 high. The remaining
critical image records at that point concerned `perl-base`; later Debian/web
and dashboard changes still require a fresh scan before attributing further
reductions. Different tools and repeated scan records may overlap.

### Real AI proposal decision

Task `fff5d609-7f89-4594-a341-7f61b2c2cdba` used `openai/gpt-oss-20b` and opened
sg-bench PR #1 from scan #283. Base:
`85dffdfb59c2aba2d32d3a5e97555f5278ca8f6c`; head:
`cbf9695de094d83731514575e8e00d8a8e2eb733`. Its 11 numbered conversation parts
covered all **179 stored findings exactly once**. Jenkins **#363** scanned the
exact head in administrator-only review mode and completed SUCCESS without
queuing another AI task.

The candidate changed `load(blob)` from pickle to JSON without a reviewed
client/data migration and changed password hashing to plain SHA-256. These
changes are unsafe despite signature preservation and scanner success.
PR #1 was **closed without merging**, and its 16 `pr_opened` finding records
were reset to `open`. The scan returned to `complete`; no finding was marked
fixed. Private decision evidence: `reports/ai-pr-review-20261001.json`.

VigilentOps PR #18's unchanged head
`b14bc47ce1c6a81c4682af92f4bd693d48cee1d5` was also closed without merging.
Its previously reproduced B107/B310 findings remain unresolved; five proposal
records were reopened. The 50 older conversations were left unchanged.

These outcomes establish a reviewed **rejection**, not an accepted real AI
fix. New bounded contract gates reduce these observed mistakes; they cannot
prove general behavior, client compatibility or cryptographic correctness.
Full finding dispositions, an accepted real fix, restored service access and
exact final-release coverage/parity remain open in [the checklist](../CHECKLIST.md).

### Subsequent full scan and container corrections

Jenkins **#364** completed SUCCESS at `ab6c0b0`; scan **#286** completed with
**285 finding records, zero critical and 54 high**. This verifies the combined
dependency, Debian and Vite corrections in the current pipeline's scanned
scope. It does not establish coverage of every deployed image: the image
stage still builds the first Dockerfile.

The remaining high records included Checkov missing-healthcheck/root-user/
workflow-permission checks, vendored packaging tools and OS advisories with
no reported fix. Commit `9b52794` removes unused Docker/curl packages from the
API/AI image, removes unused setuptools/wheel bootstrap tools after dependency
installation in the three Python images, defines application image health
checks, runs dashboard Nginx as its unprivileged user, and limits GitHub
workflow permissions to contents read. API HTTP image probes are disabled in
worker services because those processes do not serve the API. These final
container corrections require their own build/deployment/rescan results.

The container changes built successfully on Kali, and all 96 tests passed
again at `9b52794` and the documentation checkout `6aa46a2`. Migration rerun
exited zero. Jenkins **#365** / scan **#287** completed at `6aa46a2` with
**280 records, zero critical and 45 high**.

The live dashboard check exposed a rootless startup failure: the new Nginx
base uses `/run/nginx.pid`, while the initial adjustment expected
`/var/run/nginx.pid`. Correction `83b5434` replaces the PID directive
independently of that path. Its dashboard build, Nginx syntax and live startup
passed. Dashboard UID is 101; API, CVE, proxy, dashboard and Jenkins were
healthy, and both workers were running with their new images. All eight
monitoring targets and 22 Grafana queries passed again. A Kali browser using
an isolated imported lab CA verified all four tabs, pagination and search
with zero JavaScript errors/failed requests. TLS verification remained enabled.

GitHub, Kali and Gitea matched at
`83b5434c8db1b7e7c21a2896efb8235b33443edd` before this documentation update.
A real HTTPS Gitea push triggered its scan; test deliveries queued the other
12 targets for fresh coverage of that exact shared pipeline revision.
Results must be checked before accepting the final coverage gate.

The owner clarified that the target repositories are currently used for
testing. No target application deployment was identified in this session.
This narrows runtime prioritization; it does not accept unresolved findings
or establish that an undeployed project's vulnerable dependency is safe.

### Shared-pipeline coverage and accepted SQL correction

Jenkins **#379–391** / scans **#289–301** completed successfully for all 13
current default-branch heads using shared pipeline
`83b5434c8db1b7e7c21a2896efb8235b33443edd`. The strict coverage audit passed;
its private record is `reports/coverage-final-code-20261001.md`. Earlier test
deliveries through a localhost URL correctly failed the trusted-origin guard
before creating scans. Retries used the configured public origin; the guard
was retained. Subsequent commits require their own coverage evidence.

The rejected sg-bench proposal was corrected on its existing branch to retain
only the SQL parameterization in `get_user`. Every other AST statement and
function matches base `85dffdf`. SQLite checks on Kali covered string/integer
IDs, three injection payloads and preservation of the users table. The
original B608 was reproduced, then absent from the corrected candidate.
Jenkins **#392** / scan **#302** completed on exact head
`652da8b0e04440a52c383a588bb7e4a3194d540d`; no new Bandit/Semgrep findings
appeared. PR #1 was marked ready and merged after review as
`bbbb52f9ef414ef618dd110baeed25840beb2e39`. This is an accepted **AI-assisted,
manually corrected** fix. It does not validate the rejected deserialization,
password or shell changes. Those findings remain open. Private evidence:
`reports/sg-bench-sql-review/review.json`.

Jenkins **#393** / scan **#303** subsequently completed on the merged default
head `bbbb52f`. B608 and the three SQL Semgrep records were absent. Only the
four reproduced SQL records from scan #283 were marked fixed after that
verification. The other 175 records in scan #303 remain open.

### Fresh recovery and deployed cache cleanup

Private snapshot `~/secureguard-backups/lab-20261001-114129` records checkout
`572cfc4` and the exact pre-cleanup runtime image IDs. Both workers finished
their active work before stopping; the snapshot paused persistent writers
and resumed them afterward. The isolated database/volume drill matched
**123 table counts and eight archives**.

The new core service-access drill initially exposed premature inventory
polling and Grafana provisioning permissions under the private extraction
umask. Both were corrected in the recovery helper. The completed drill
recovered **13 Gitea repositories, one Grafana dashboard and one Jenkins job**
with native authentication. Jenkins had zero executors, stayed quiet and
denied anonymous API access. The disposable internal network had no published
ports, Docker socket or outbound access; all drill resources were removed.
Private result: `reports/restored-service-access-20261001.json`. This verifies
core logins/inventory, not every restored workflow or datasource query.

The cache-cleaned `c32027f` images then deployed after graceful worker
shutdown and an idle Jenkins check; migrations exited zero. Live API, CVE,
proxy, rootless dashboard and Jenkins were healthy; workers resumed. All
eight Prometheus targets and 22 provisioned Grafana queries passed again.
Compose validation and the 96-test suite passed on Kali at `f6b6cb6`.

### Live failure handling and deployed image inventory

A temporary Jenkins job copied the shared pipeline's actual Upload Reports
stage at `83b5434`. Its malformed SARIF upload returned **422**; build 1 ended
FAILURE, scan **#304** ended `failed`, and no findings or accepted reports
were stored. The fixture job was deleted afterward. Private evidence:
`reports/jenkins-upload-rejection.json`. This checks the actual rejected-upload
path, independently of the earlier positive scans and Python fixtures.

Jenkins **#395** was observed after Dependency-Check completed and before
workspace cleanup: its temporary NVD key properties file was absent while the
SARIF report was still present. No key contents were read. Private evidence:
`reports/nvd-secret-removal-build395.json`. Historical provider-key rotation
remains a separate unperformed action.

The new deployed-image helper inventoried **25 exact image IDs** across all
existing Compose containers, including stopped services. Both Trivy and
Dockle reports passed validation for every ID. Scanner/report permission,
Dockle reference and offline cache-path errors from earlier attempts were
corrected before accepting the completed audit. The persistent Trivy feed
was updated at `2026-10-01T01:24:14.992991033Z`; the combined private record
is `reports/deployed-image-coverage.json`. These reports are separate private
artifact audits, not orchestrator scan receipts or resolved findings.

The private 13-repository triage inventory under
`reports/triage/default-heads-20261001` recorded **130 critical and 2,215 high
finding records**, not unique vulnerabilities. The completeness checker
failed because records still need reviewed dispositions, evidence and real
owners. Testing-only use does not authorize their acceptance.

### Jenkins security upgrade

The screenshot's controller was Jenkins 2.555.3 with older persistent plugins.
The image now pins **2.580.1 LTS / Java 25** by registry digest; all **97**
existing plugin names have compatible version pins. The official image's
reference-plugin upgrade flags ensure newer managed versions reach the
persistent home. See [Jenkins upgrades](JENKINS_UPGRADES.md).

Before deployment, the new image passed an isolated restored-volume rehearsal,
including the snapshot's native security startup script, authenticated service
inventory, enabled-plugin activation and quiet Jenkins with zero executors.
An idle pre-upgrade volume/private configuration backup was then taken at
`~/secureguard-backups/pre-jenkins-upgrade-20261001-121746`; its checksums and
archive readability passed. The old image is retained for coordinated recovery.

Live core was **2.580.1**, Java **25.0.4.1**, all 97 plugin versions matched,
and every enabled plugin was active. Evaluating official update-center warning
patterns against installed versions found **zero applicable known warnings**.
The Manage page had no security-warning block or Java 21 end-of-life notice.
This is installed-version advisory evidence, not a clean container image claim.
The shared declarative pipeline parser passed. Native network checks returned
403 for anonymous API access, 200 for administrator API/metrics scrape, and
403 for metrics-account administration. Private evidence:
`reports/jenkins-lts-live-acceptance.json` and
`reports/jenkins-native-access-after-upgrade.json`.

A real HTTPS Gitea push at `a7f4dec` triggered Jenkins **#395**, which finished
SUCCESS; scan **#306** completed with **342 records, zero critical and 45 high**.
All eight targets and 22 Grafana queries passed after the controller upgrade.
The 96-test suite also passed on Kali at `a7f4dec`.

The first upgraded image's separate Trivy audit reported a critical advisory
in its unused `openssh-client`. The controller uses the built-in node and
accepted HTTP/HTTPS clone URLs, so `56993b7` removes that package while keeping
Git. The exact rebuilt runtime image
`sha256:bbed5a3a20a6` (full ID retained privately) deployed healthy with all
97 plugin pins active. Both Trivy and Dockle accepted its reports; Trivy
recorded **zero critical, 92 high, 155 medium, 159 low and 17 unknown**.
The removed client's advisory was absent. Remaining image findings still
require review. Private evidence: `reports/jenkins-no-ssh-audit-20261001`.

### Gateway package update

The gateway now pins stable **Nginx 1.30.5** by digest. Its exact candidate
image `sha256:43d9d8c1f896` was also the deployed image after configuration
syntax validation; the old image was retained under a rollback tag. Trivy
reported **zero critical, one high and one unknown**; the previous OpenSSL
advisory was absent. Dockle accepted the deployed image's report. These
scanner labels do not establish exploitability: the OpenSSL vendor described
the removed advisory as low severity and specific to 32-bit systems.

After recreation, public-IP TLS verification, authenticated gateway routes,
HTTP-to-HTTPS 308, HTTPS Git read and Grafana Live **101** passed. All eight
targets and 22 panel queries passed. Running Compose containers publish only
gateway **3000**; TCP checks found **17** old listeners closed. A stopped
legacy SonarQube container retains historical port metadata but has no live
listener. Private records: `reports/gateway-stable-route-acceptance.json`,
`reports/gateway-monitoring-nginx-upgrade.json` and
`reports/gateway-dockle-upgraded-20261001`.

The version selections follow the official [Jenkins LTS download](https://www.jenkins.io/download/),
[Java support policy](https://www.jenkins.io/doc/book/platform-information/support-policy-java/)
and [Nginx stable release listing](https://nginx.org/en/download.html).
The [OpenSSL vendor advisory](https://openssl-library.org/news/vulnerabilities/)
provides the severity/platform qualification above.

### Post-upgrade checkpoint

At **`3bae893714598db146de101e047a51e9a4f9cfb0`**, Kali passed Compose
validation, dashboard/service/Jenkins builds, migrations and all **96 tests**.
GitHub, Gitea and the server checkout matched. A real HTTPS push triggered
Jenkins **#396**, which finished SUCCESS with the cleaned controller image;
scan **#307** completed on that exact target/shared pipeline commit. It stored
**13 report receipts** and **342 findings: zero critical, 45 high, 120 medium,
165 low, ten informational and two unknown**. This confirms HTTP/HTTPS Git
and scanner execution after removing the unused SSH client.

All eight monitoring targets and 22 panel queries passed again. The final
private image inventory reconciled every existing container's exact image ID
against matching accepted Trivy/Dockle reports, including the upgraded gateway
and Jenkins: **25 image IDs**. Private records:
`reports/acceptance-3bae893.json`,
`reports/jenkins-final-image-pipeline.json`,
`reports/gateway-monitoring-final-images.json` and
`reports/deployed-image-coverage-final.json`.

The refreshed private export
`reports/triage/heads-after-jenkins-upgrade-20261001` matched all 13 current
default-branch heads, including VigilentOps scan #307 and merged sg-bench
scan #303. Totals remain **130 critical and 2,215 high records**. Each review
file was preserved privately; completeness remains FAIL until actual reviews,
owners and supported disposition evidence are supplied.

Subsequent documentation changes do not change the recorded runtime scope.
This checkpoint does not declare release completion: unresolved target and
deployed-image findings, owner-backed dispositions, historical credential
rotations and the remaining checklist gates still require work.
