# Server acceptance progress — 26 September 2026

This record captures the Kali server run against `fd458f4ff26ebdb04758b23f1f21cfa7250f7852`.
It is **not** a completed lab acceptance. The next Jenkins run must use the
later commit that adds NVD key forwarding and a persistent Grype cache.
Raw findings and credentials remain on the server.

## Verified on the server

| Check | Evidence | Result |
| --- | --- | --- |
| GitHub and Gitea `main` commit | Both `fd458f4ff26ebdb04758b23f1f21cfa7250f7852` | Pass; GitHub egress timed out, so a bundle of the already-pushed commit was fast-forwarded on the server and pushed to Gitea |
| Compose configuration and Python/shell syntax | `docker compose config -q`; 15 Python files parsed; `bash -n scripts/setup-kali.sh` | Pass |
| Changed service/Jenkins builds | `docker compose build --quiet dashboard migrate orchestrator celery-worker cve-intel wazuh-proxy jenkins` | Pass |
| Python regression suite | Newly built orchestrator image, `python -m unittest discover -s tests -v` | 29/29 passed |
| Migration and service startup | `docker compose --profile ci up -d ...`; migrate exited successfully; orchestrator/CVE healthy | Pass |
| HTTP clients | Orchestrator `/health`, CVE `/health`, dashboard `/`, Jenkins `/login` | HTTP 200 each |
| Grafana authentication and provisioning | Authenticated API: health, one SecureGuard dashboard, Prometheus/Loki/Infinity data sources | HTTP 200 |
| Grafana Wazuh, CVE, and Prometheus panels | `/api/ds/query` using the provisioned panel queries | HTTP 200; Wazuh one frame, CVE one frame, Total Scans seven frames; no datasource error |
| Wazuh and CVE network clients | Proxy `/_proxy_health`, `/sca/000`, CVE `/cves/recent` from Compose network | HTTP 200; CVE endpoint returned 50 items |
| Coverage inventory | `scripts/audit_scan_coverage.py` | 13 Gitea repos, each with an active push hook; fresh terminal scan coverage is incomplete |
| Private triage export | `scripts/export_scan_triage.py 235` | 3,351 records, 2,570 suggested review groups; 239 high, 1,979 medium, 1,133 low |
| PostgreSQL backup and isolated restore | Private 30,070,269-byte custom-format dump; disposable PostgreSQL 15 container | Restored 237 scan rows and 101,021 finding rows, matching live counts; test container removed |
| Gitea/Jenkins/Grafana volume archives | Private server archives: 1,453,608,448 / 812,168,704 / 102,121,984 bytes; mode 0600 | Restored into disposable volumes; archive and restored entry counts matched (7,831 / 6,160 / 689); live services returned after restart |

## Failed or still open

- Jenkins build **#310** for scan **#237** ended `FAILURE`; scan #237 is
  terminal `failed` with zero uploaded findings. This is correct fail-closed
  behavior, not scanner acceptance. Dependency-Check returned exit code 13:
  NVD data update failed, CISA DNS lookup failed, and its persistent cache was
  only about 1.2 MiB with no usable vulnerability documents.
- Grype's container waited about 14 minutes on an Anchore TLS handshake. It
  was stopped after the build had already failed; the next pipeline revision
  adds a persistent Grype DB cache and bounded update waits.
- The CVE service's NVD request also failed, although its CISA KEV request
  succeeded. A real NVD API key is present in the private server `.env` and
  will be forwarded to Jenkins by the next Compose revision. External feed
  connectivity must still be demonstrated.
- Snyk is intentionally disabled in this lab (`SNYK_TOKEN` is empty).
- The 13 repositories have active hooks, but most last scans are old. Latest
  failures include `Netflix-zuul` and `sietlms-moodle-`; `Portfolio` and
  `browser-use` remain stale `running`; `SIET-Hackathon` has no scan. Historical
  `ShadowPatch` is not in the current Gitea inventory.
- Scan #235 predates the current commit and scanner contract. Its 3,351
  records are a triage baseline, not current release findings. Of 239 high
  records, 223 are from Trivy image, eight from Trivy dependencies, and eight
  from Grype. These overlap and do not count unique vulnerabilities.
- AI PR head validation, all finding dispositions, full application recovery drill, alert
  routing, and production hardening remain open. The database and archive
  extraction drills passed; an isolated **application startup** from all
  restored volumes remains to be proven before claiming full recovery.

Continue with [the server acceptance record](SERVER_ACCEPTANCE.md) after the
new commit is deployed. Keep the private coverage and triage files under
`reports/` on the server; do not commit raw finding descriptions.

## Follow-up run in progress

- Commit `9e08ae36883073ea972ace09970c92787e347fe6` is on GitHub,
  Gitea, and the server. Gitea push triggered Jenkins **#312** and
  orchestrator scan **#238**. Dependency-Check began the first NVD download,
  reaching at least 20,000 of about 398,000 records. This is progress, not a
  valid Dependency-Check report or completed scan.
- Grype, Dockle, OSV, Semgrep, Bandit, Gitleaks, Checkov, and SBOM files were
  visible in the Jenkins workspace. Trivy dependency and image reports were
  missing because the database download from the default registry timed out.
  Jenkins #312 was still running when this section was written, so its final
  result and uploaded findings remain unverified.
- A Jenkins process inspection revealed that the previous `--nvdApiKey`
  argument exposed the key to server operators. Rotate that NVD key after
  this run. Commit `4eba162789c53b95ad7483fefdcbef62b3a7c9dc` is now on
  GitHub, Gitea, and the server; it removes the key from process arguments,
  clears old report files, and restricts clone URLs. Its queued Jenkins run
  later ran as build **#313**. It failed because the protected key file was
  owned by Jenkins UID 0 while Dependency-Check runs as UID 1000, so the
  scanner could not read the mode-0600 file. A follow-up change assigns the
  file to UID 1000 before starting that container.
- Jenkins **#312** finished `FAILURE` and scan **#238** is terminal `failed`.
  Dependency-Check reached analysis and attempted to write SARIF, but CISA DNS
  and NPM Audit lookup errors contributed to an exit 14 report failure. Its
  report was not accepted. Build **#313** and scan **#239** also failed on the
  key-file permission error; no complete report set was uploaded.
- Commit `3cdfb6fcf1a339a550d5736ef34df854b75cd8c3` reached GitHub,
  Gitea, and the server. Jenkins **#314**, scan **#240**, started the new
  Trivy database prewarm stage. A separate server cache fill from Trivy's
  official Docker Hub registry reached 64% of the 117 MiB database before the
  default five-minute timeout stopped it. The Jenkins stage uses a longer
  timeout and was downloading when this section was written. Completion and
  both Trivy SARIF reports remain to be verified.
