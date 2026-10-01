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

Prepared changes include scanner version selection and digest inventory,
report completion before AI, receipt coverage in scan details, generic API
failures, and notification delivery outcomes without raw source/descriptions.
AI source resolution rejects symlinks and `.git` metadata; write validation
preserves UTF-8 and the guarded interfaces. Model compatibility and real fix
quality still require separate checks. See [Next server session](NEXT_SERVER_SESSION.md).

Do not merge PR #18 unchanged or mark the lab complete until repository
coverage, finding dispositions, reviewed AI fixes, recovery and exact commit
parity have evidence. Credentials and raw logs remain private.
