# Server acceptance progress — 1 October 2026

This record is incomplete. Builds and tests run only on Kali; no runtime
result from earlier commits proves the pending changes work.

| Check | Evidence | Result |
| --- | --- | --- |
| SSH and repository inspection | Previously verified SSH host key at `10.20.29.248`; branch `Features`, clean tracked checkout at `7bcfd0c6412535d8ac5b5a540c0b973a1aff785b` | Pass before deployment |
| Initial service inspection | Core services running; Falco and its exporter restarting | Runtime monitoring needs repair |
| New code acceptance | Pending server backup, image builds, expanded suite, migrations and live checks | Not established |

Prepared changes include scanner version selection and digest inventory,
report completion before AI, receipt coverage in scan details, generic API
failures, and notification delivery outcomes without raw source/descriptions.
AI source resolution rejects symlinks and `.git` metadata; write validation
preserves UTF-8 and the guarded interfaces. Model compatibility and real fix
quality still require separate checks. See [Next server session](NEXT_SERVER_SESSION.md).

Do not merge PR #18 unchanged or mark the lab complete until repository
coverage, finding dispositions, reviewed AI fixes, recovery and exact commit
parity have evidence. Credentials and raw logs remain private.
