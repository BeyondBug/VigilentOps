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
