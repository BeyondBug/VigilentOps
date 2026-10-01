# Server acceptance progress — 1 October 2026

This record is incomplete. Builds and tests run only on Kali; no runtime
result from earlier commits proves the pending changes work.

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
