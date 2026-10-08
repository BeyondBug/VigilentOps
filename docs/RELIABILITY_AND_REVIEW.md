# Reliability and evidence-based review

All scanner severities remain visible. A scanner result is a lead, not proof of exploitability; no model or scanner can guarantee zero false positives or zero crashes. Review decisions preserve the original result and severity, record owner/evidence, and append versioned history. Default status is `unverified`.

The Findings page filters by `unverified`, `confirmed`, `false_positive`, `accepted_risk`, or `fixed`. Reviewing never reduces the original severity or scan counters. False positives and accepted risks are excluded from new AI proposals. Existing proposals remain available for human review.

On Kali, create a private text file with reproduction or exclusion evidence, then run:

```sh
python3 scripts/review_finding.py FINDING_ID confirmed --owner YOUR_NAME --version 0 --evidence-file /private/path/evidence.txt
```

Use the `review_version` returned by `/dashboard/api/findings` for subsequent updates. A stale version returns HTTP 409. Review writes require the server's private API key; the CLI reads it inside the orchestrator container. No key belongs in the browser or Git.

For `accepted_risk`, supply `--details-file` containing a JSON object with `impact`, `mitigation`, and an ISO `review_date` today or later. The dashboard displays that date; operators must revisit expired exceptions (expiration is not automatic).

For `fixed`, details must contain an exact 40-character `tested_commit` and `verification_scan_id`. The API requires a completed, accepted scan of the same repository at that commit, all required report receipts, the original scanner actually running, and no matching finding in that rescan. Absence in one rescan remains bounded by that scanner's coverage.

AI modes are `off`, `openrouter`, `local`, and `hybrid`. An existing private OpenRouter key without an explicit mode retains cloud-only behavior. New `.env.example` installations default to `off`. Local inference requires explicit opt-in. Cloud models must belong to the explicit allowlist; each OpenRouter request enforces zero prompt/completion/request prices. Provider availability and shared quota are external dependencies. No repository-source requests should be made until the operator chooses and configures the mode.

Truncated provider output, error envelopes, weak password-hash suppression, unsupported contract migrations, and partial removal of targeted Bandit rules are rejected. Proposed code still requires human review and target-project tests; Python syntax and Bandit are insufficient to establish runtime equivalence. AI task admission serializes per scan, returns the same task ID for repeated requests, and rolls back reservations when broker publication fails. Completed tasks require a new scan to request another proposal. After a broker loss or hard worker kill, inspect the persisted task ID against Celery before administratively recovering a stale reservation; never blindly enqueue a second writer.

Scan CVEs are aggregated from database findings rather than summary-only scan payloads. The page explicitly shows its recent-100-scan scope and 200-CVE display cap. Feed HTTP failures are visible. NVD pagination is sequential, bounded, and fails on incomplete windows. Failed CISA requests preserve existing KEV membership; successful snapshots reconcile membership. New alert event keys prevent duplicate deliveries. Historical alerts are preserved. The polling lookback remains `POLL_HOURS + 1`; a prolonged outage needs an explicit backfill.

Gateway dashboard/Prometheus credentials are stripped before those upstreams. Jenkins uses the private bootstrap gateway login as its native account, so its authentication header is retained for authenticated API and backup operations. Gitea uses a private token; no hardcoded password fallback remains. Container logs rotate at 10 MB × 3 per container after recreation.

Edit on the laptop, publish a candidate GitHub branch, fetch it into an isolated Kali worktree, and run the full unit suite plus Docker/dashboard builds before merging. Back up private configuration, databases and volumes before live migrations. Preserve server-only configuration and Gitea history. After deployment, rerun health, authenticated gateway, database/migration, monitoring and AI failure-mode checks. Evidence belongs outside Git when it contains private operational data.
