# Server acceptance progress — 30 September 2026

This is an interim record from the Kali lab server. It does **not** establish
project completion. The server address changed to `10.20.29.248`; its SSH host
fingerprint matched the previously verified host. Credentials, raw findings,
and scanner logs remain off Git.

| Check | Evidence | Result |
| --- | --- | --- |
| Exact commit parity | GitHub `main`, Gitea `main`, and Kali checkout: `ef9d6cbf9b2196e926f625d9f36de95e5658dcb5` | Pass at this commit; recheck after future pushes |
| Compose configuration | `docker compose config -q` on Kali | Pass |
| Service and Jenkins images | `docker compose build --quiet dashboard migrate orchestrator celery-worker cve-intel wazuh-proxy jenkins` on Kali | Pass |
| Python regression suite | Kali orchestrator image, `python -m unittest discover -s tests -q` | 29 tests passed |
| Service health | Orchestrator `/health` and CVE `/health` | HTTP 200; database OK and CVE feed count 11,736 |
| Migration and web endpoints | Migration container exited 0; dashboard `/` and Jenkins `/login` | HTTP 200 for both web endpoints |
| Current repository inventory | Private `scripts/audit_scan_coverage.py` output | 13 Gitea repositories, all with active push hooks; fresh terminal scan coverage incomplete |
| Stale scan reconciliation | Scans #185 (`browser-use`) and #222 (`Portfolio`) were hundreds of hours old and had no active build | Both changed from `running` to `failed`; new scans still required |

## Scanner run

- Jenkins #315 failed because Dependency-Check produced no valid SARIF report.
  Its Trivy dependency, Trivy image, and Dockle reports were generated but not
  uploaded as a complete accepted report set.
- Jenkins #316 timed out after about 120 minutes during the first NVD database
  download. Scan #242 was manually reconciled to `failed`. Commit `ef9d6cb`
  adds an aborted-build status handler for later runs.
- A Gitea push of `ef9d6cb` triggered Jenkins #317 and scan #243.
  Dependency-Check downloaded 110,000 of 399,513 NVD records, then failed
  with repeated NVD request errors and DNS lookup errors for CISA and
  RetireJS. Jenkins #317 ended `FAILURE`; scan #243 ended `failed`. Required
  report validation and upload were skipped, so this is not an accepted scan.
- While Dependency-Check ran, its temporary NVD properties file was owned by
  UID/GID 1000 with mode 0600. Verify its removal after the scanner exits.
- The host resolved external names through `10.20.16.1`, while Docker's daemon
  config provided `8.8.8.8` and `1.1.1.1` to scanner containers. A disposable
  Dependency-Check container successfully resolved CISA through `10.20.16.1`.
  The configured NVD key also returned HTTP 200 on a one-record keyed request.
  The optional per-container `SCANNER_DNS` setting was then applied. Its
  full-run effectiveness remains unverified.
- Jenkins #318 / scan #244 used Docker's previous resolver and was stopped
  after repeated slow NVD API retries; both ended `failed`. Jenkins was
  recreated with `SCANNER_DNS=10.20.16.1`. Build #319 used that resolver and
  reached 10,000 of 399,518 NVD records after about five minutes. Its full
  report contract was still unverified at this point.
- The official Dependency-Check mirror's modified feed returned HTTP 200 and
  transferred 3,173,579 bytes in about one second from Kali. Its 2026 feed
  returned HTTP 200 on a HEAD request with a 29,238,925-byte length and a
  29 September 2026 Last-Modified header. An optional datafeed URL is being
  prepared to avoid repeated first-load REST API failures; verify the mirror
  is fresh enough before release.
- Jenkins #320 / scan #246 used the official mirror and downloaded the yearly
  feeds in about two minutes. It completed NVD database maintenance and the
  analysis, then failed with exit code 12 while generating SARIF. The Jenkins
  workspace report directory was created by root while Dependency-Check runs
  as UID 1000; a directory ownership fix is prepared for the next run. No
  required report set was uploaded from #320.
- Jenkins #321 / scan #247 generated a 170,250-byte Dependency-Check SARIF
  report. `Validate Reports` correctly failed because `checkov.sarif` was not
  JSON: the Checkov stage had redirected console text to that filename.
  A disposable Checkov run on Kali wrote valid SARIF 2.1.0 through
  `--output-file-path /reports` as `results_sarif.sarif`. The pipeline is being
  changed to use that native report. Scan #247 ended `failed`; uploads were
  skipped.
- The NVD and CISA endpoints responded during this run, but prior transfers
  stalled. Continue monitoring the full download before drawing a network
  reliability conclusion.

## Coverage snapshot

The private audit returned 243 scan records. The latest `VigilentOps` scan was
#243, `running`. `SIET-Hackathon` had no scan. `Netflix-zuul`, `Portfolio`,
`browser-use`, and `sietlms-moodle-` had latest status `failed`; the other
repositories' latest scans were old. A configured hook does not prove a
successful delivery or a scan of the latest commit.

## Work still required

Complete #317 or diagnose its failure, verify the full report contract and
stored findings, review a new AI PR and its complete finding conversation,
scan every intended repository, and dispose of current high findings. Then
repeat builds, migrations, client checks, backup recovery, and security gates
against the exact release commit. See [the checklist](../CHECKLIST.md).

## Later same-day results: scanner and Grafana

- Jenkins #322 finished `SUCCESS` on `a256636` and orchestrator scan #248
  reached `complete`. All required uploads returned HTTP 200. Dependency-Check
  supplied a valid 170,250-byte SARIF report; Checkov used its native SARIF
  output. Scan #248 stored 3,742 findings: 256 high, 2,189 medium, and
  1,297 low. The private triage export on Kali contains 3,742 records and
  2,917 suggested review groups.
- AI task `663e99f4-1ca5-4d6b-a59d-718b2f3fb0f9` opened Gitea PR #18.
  Its conversation has 220 numbered parts and covers all 3,742 findings
  once each. The two edited scripts passed 29 Python tests on the PR head,
  but a targeted Bandit rescan still reported the original B107 and B310
  findings. PR #18 is **not accepted for merge**.
- Gitea webhook test deliveries initiated a current scan for each of the 13
  repositories. The private `reports/coverage-20260930.md` audit on Kali
  reports seven latest scans `complete`, five `failed`, and `Range` at
  `pr_opened`. The five failed targets are Moondream, Netflix-Hystrix,
  Netflix-zuul, browser-use, and sietlms-moodle-. Jenkins #338 completed
  `SUCCESS` for VigilentOps scan #262 at `a849b8e` after the monitoring
  changes. Repository coverage and finding triage are still open.
- Before Grafana changes, a private backup directory
  `~/secureguard-backups/pre-grafana-20260930-115649` was created on Kali.
  It contains a PostgreSQL custom-format dump, Grafana and Prometheus volume
  archives, Compose/private configuration, Wazuh alerts, and Wazuh API
  configuration. All seven SHA-256 entries passed; the archives and dump
  were readable. A complete restore was not performed for this new backup.
  Gitea/Jenkins volume archives from the 26 September recovery exercise
  remain separate.
- The initial dashboard showed stopped cAdvisor, Redis, and PostgreSQL
  exporters, a histogram for a single container count, an AI PR metric that
  counted finding rows, and an empty Wazuh alert panel caused by an absent
  Promtail log mount. The exporters now use `unless-stopped`; their three
  Prometheus targets and all five other targets were `up` on Kali. The
  dashboard API returned HTTP 200 with the new scan aggregation, scanner
  labels, memory unit, running-container stat, and explicit sensor zeros.
  Every Prometheus panel query returned `success` with a series. Example
  values after deployment: 20 running containers, eight targets up, 334
  distinct historical AI PR URLs, CVE and Wazuh containers online, and
  Falco container at zero because the Kali kernel driver is unsupported.
- The CVE intelligence endpoint returned HTTP 200. The Wazuh SCA proxy
  returned HTTP 200 with one policy, and Loki returned two Wazuh log entries
  in the selected six-hour range. Wazuh API configuration and alert logs now
  have persistent private volumes. Its manager and proxy were recreated,
  and the configured Wazuh API password, certificate trust, and SCA result
  were verified afterward. Grafana panel titles now describe recent CVEs
  accurately; the feed does not establish that those CVEs were fixed.
- A second forced recreation of Wazuh and its proxy confirmed the persistent
  API volume: configured authentication and the SCA endpoint both returned
  HTTP 200, and Promtail still read the growing alert file. The unsupported
  Falco kernel driver remains a separate runtime-sensor limitation.

## HTTPS gateway acceptance

The gateway implementation at `f76980f` and Jenkins route protection at
`49ee067` were deployed from GitHub through the Kali checkout to Gitea.
All builds and runtime checks were performed on Kali.

| Check | Evidence | Result |
| --- | --- | --- |
| Published application ports | Docker inspection found only `sg-gateway`, `3000/tcp` mapped to host 3000 | Pass |
| Removed service listeners | TCP connections to 2222, 3001, 3002, 3100, 8000, 8001, 8081, 8082, 9090, 9091, 9121, 9187, 9376, 1515, 50000 and 55000 failed | Pass; host SSH is separate |
| TLS | HTTPS requests verified against the generated private lab CA, including the public server IP and localhost | Pass |
| Password boundary | Anonymous dashboard, Prometheus and Jenkins management requests returned 401; the public Jenkins trigger endpoint returned 404 | Pass |
| Findings UI and APIs | Authenticated dashboard HTML, its `/dashboard/static/` JavaScript asset, scan summary and CVE feed returned 200 | Pass |
| API write guard | A gateway-authenticated scan creation without `X-API-Key` returned 401 | Pass |
| Native services | Gitea login/root, authenticated Jenkins login/job API and Grafana login/health returned 200 | Pass |
| Grafana panels | `/grafana/api/ds/query` returned HTTP 200 with 32 query results, all with data frames and no errors; CVE, Wazuh SCA and log panels included data | Pass |
| Grafana Live | Authenticated WebSocket upgrade through the gateway returned HTTP 101 | Pass |
| Prometheus | All eight scrape targets were up, including Jenkins at `/jenkins/prometheus` | Pass |
| Metrics history | Prometheus retained its previous anonymous volume `314ee5e02045e8f6eb2dade8b3e7bc7aa46d8dbe94dbaa94cd522edf24d73246` | Pass |
| Server tools and Git | HTTPS `git ls-remote`, coverage audit and scan #263 triage export succeeded; the export contained 3,743 records | Pass |
| Gitea hooks | All 13 active push hooks use the prefixed internal Jenkins endpoint. A Gitea test delivery returned 204 and started Jenkins #340 | Pass |
| Pipeline after migration | Jenkins #340 finished SUCCESS; scan #264 completed at `f76980f810e5ec2d297641cc4787ddba369d46eb` | Pass |
| Real HTTPS Git push | Pushing `49ee067` from Kali to Gitea over HTTPS triggered Jenkins #341, which completed SUCCESS | Pass |
| Old HTTP bookmark | Plain HTTP on port 3000 returned 308 to HTTPS on the same port | Pass |
| Regression checks | Compose validation, Nginx syntax, the dashboard build and all 29 Python tests ran on Kali | Pass |

The private pre-proxy backup at
`~/secureguard-backups/pre-proxy-20260930-145430` contains the database dump,
previous host configuration, Gitea configuration and webhook definitions,
Jenkins job/location configuration, Wazuh API state and container metadata.
Its checksums passed and the PostgreSQL dump was readable. The new gateway
private keys, credentials and configuration were also archived separately at
`~/secureguard-backups/gateway-20260930`. Neither backup was committed to Git.
These backup integrity checks do not establish a complete restore drill.

Inspection found Jenkins's stored realm/authorization strategy were
`None`/`Unsecured`. The gateway now authenticates every public Jenkins route
and strips that credential before forwarding it. Gitea invokes Jenkins on
the internal Docker network; its public trigger route is blocked. Native
Jenkins user accounts and permissions remain a production gate.

Only application port 3000 is published by this Compose project. Host SSH,
unrelated host services, and firewall policy are managed separately. Gitea
SSH and external Wazuh agent transports are no longer published. Their
replacement/access requirements are described in [Gateway setup](GATEWAY.md).
The existing Falco limitation and five failed target repository scans remain
listed in the checklist.

## Latest handoff: server unavailable, code preparation continues

Kali and Gitea received `7bcfd0c`. At that commit Compose validation and
33 Python tests passed on Kali. The scanner changes distinguish OSV's
no-supported-package result, increase bounded Trivy timeouts and exclude only
Moodle's malformed/encrypted ZIP fixtures from Dependency-Check. These changes
still require fresh accepted scans for the five failed repositories. An
interrupted rerun command may have queued some deliveries; outcomes were not
confirmed before connectivity became unavailable.

Falco inspection found the engine explicitly configured as `nodriver`.
BTF was present on the Kali host. The modern eBPF configuration was applied
and the container started, but stable operation/event capture was not verified.
The earlier unsupported-driver explanation must not be treated as established
by this inspection.

Further code is prepared for native Jenkins accounts/permissions/CSRF,
credential-backed hooks and authenticated metrics; scanner artifact metadata,
report receipts and completion gates; Bandit/interface candidate checks,
Git credential handling and PR-head review scans; private triage checks,
controlled AI retry/fallback checks and backup/isolated restore automation.
Documentation and the checklist describe these changes. They have **not** been
built, tested or deployed. No local builds/tests were run. The project remains
incomplete until [Next server session](NEXT_SERVER_SESSION.md) and the required
[checklist](../CHECKLIST.md) gates have recorded evidence on the release commit.

A subsequent offline review corrected scanner stages that discarded execution
exit codes, tightened scan-coordinate validation and AI queue eligibility,
fixed startup metrics attribution/count replay, and added restore-manifest
preflight before Docker resource creation. These are code changes with prepared
regression checks, not new acceptance evidence. No laptop builds/tests or
additional server actions were performed.

## Additional offline preparation: static lint coverage

Hadolint 2.15.1 and ShellCheck 0.11.0 are integrated into the shared pipeline,
required report contract, API quality findings and future whole-scan PR
conversations. No-file targets receive explicit not-applicable receipts.
Target checkout cleanup and Docker bind commit verification guard against
stale/wrong source mounts. The scanner chart now groups all scanner labels;
findings filters include INFO and UNKNOWN. Additional checks were written for
Kali. **No images, builds, application checks or tests were run on the laptop.**
Server compatibility, report coverage and rendered charts remain unverified.
Follow [Next server session](NEXT_SERVER_SESSION.md); earlier acceptance does
not establish success for these code changes.
