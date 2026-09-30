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
  An optional per-container `SCANNER_DNS` setting is prepared for the next
  scan; its full-run effectiveness remains unverified.
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
