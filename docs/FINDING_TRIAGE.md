# Finding triage and lab acceptance

Use this policy with the private export from
[Testing](TESTING.md#database-verification). Scanner records are evidence to
review, not a count of distinct exploitable vulnerabilities. The export
groups by advisory/rule and path as a starting point; confirm affected package,
version, container image, and exploit conditions before merging records.

On 1 October, the project owner confirmed that all 13 current Gitea targets
are real projects. Do not classify their findings as intentionally vulnerable
lab examples or automatically accept them on that basis. `ShadowPatch` is
historical scan scope; `SIET-Hackathon` is in the current repository inventory.
The owner subsequently clarified that these target repositories are currently
used for testing. No target application deployment was identified in this
session. Prioritize the deployed SecureGuard services separately from target
source/dependency findings, and verify actual runtime use before assigning
exploitability. Testing scope does not automatically resolve or accept a finding.

## Review order

1. Confirm secrets first. Revoke exposed credentials and remove the active
   exposure; suppressing a scanner result alone does not resolve a secret.
2. Review critical and high findings in deployed runtime images and reachable
   dependencies. Confirm the affected version and a safe replacement.
3. Review high source-code findings against the actual call path. Test a fix on
   the proposed branch and rescan before calling it resolved.
4. Review medium and low findings, including duplicate reports and development
   dependencies. Record the decision for each review group.

## Dispositions

Use one of these values in `review-groups.csv`:

- `fixed`: linked to a tested commit and a later scan that no longer reports
  the affected artifact.
- `accepted`: documented reason, impact, mitigation, named owner, and a
  review date. An accepted issue remains a known risk.
- `not_affected`: evidence that the component/version/path is not used or
  vulnerable in this deployment.
- `duplicate`: link to the primary group with the same underlying issue.
- `open`: investigation or remediation is still pending.

Keep the original scanner record IDs and advisory IDs with every decision.
Do not mark an AI PR as `fixed` until its branch has passed review and server
validation.

## Lab release gate

- Every critical, high, and secret finding must have a verified `fixed`,
  `not_affected`, or documented `accepted` decision. A duplicate points to
  one of those reviewed primary groups. No critical/high record may remain
  untriaged.
- Every medium finding must have an owner and a planned fix or a documented
  exception with review date. Low findings need an owner and backlog entry.
- Required scanner reports and uploads must pass the current Jenkins contract.
Optional scanner coverage must be stated in the release record.
- The final server scan, dashboard, monitoring checks, and reviewed AI PR
  branch must pass the acceptance steps in [Testing](TESTING.md).

These gates describe completion of the **lab**. Production exposure also
requires the additional controls in [CHECKLIST.md](../CHECKLIST.md).

## Structured exports and completeness check

New scans preserve available package, installed/fixed version and image fields.
The exporter includes those fields in private CSVs and suggested group keys;
older rows stay blank. Scanner formats can omit metadata, so verify the raw
report and deployment context rather than treating blank fields as unaffected.

Fill `owner`, `disposition` and evidence in `review-groups.csv`. Fixed groups
require `tested_commit` (full SHA), `verification_scan_id` and `evidence`;
accepted groups also require `impact`, `mitigation` and a current `review_date`.
Duplicates use `duplicate_of` with evidence linking a reviewed primary group.
Open medium/low groups need a `planned_fix` or backlog reference.

Run on Kali after manual review:

```bash
python3 scripts/check_triage.py reports/triage/final
```

It checks that every exported finding appears exactly once, owners/evidence
are present and high/critical/secret/unknown records are dispositioned.
It never updates findings, approves an exception or proves the evidence valid.
Keep both CSVs private and preserve the original export for audit.

## Lint findings

Hadolint and ShellCheck findings use the `quality` class. Native error levels
map to MEDIUM, warnings to LOW, and informational/style levels to INFO. These
labels prioritize review; they do not establish exploitability, a CVE or a
CVSS score. Review the actual diagnostic and context, especially parser errors
and suppressed shell diagnostics. They appear in private exports and future
whole-scan PR conversations but are outside Python automatic patch scope.

## Evidence-confirmed reporting

The product dashboard defaults to evidence-confirmed findings. Raw alerts stay
under **Show all scanner alerts (includes unverified)** and retain their original
severity, report receipts and audit history. Older `confirmed` reviews without
structured reproduction evidence appear as `review only`; they are not promoted
or deleted. A zero confirmed count means evidence is absent, not that scans proved
safety. External NVD feed entries are advisories, not project vulnerabilities.

To confirm a security finding, an authenticated operator must record a controlled
reproduction at the exact scanned commit. Put these fields in a private JSON file:

```json
{
  "tested_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "verification_method": "controlled_reproduction",
  "artifact": "app.py",
  "proof_reference": "private/reproductions/finding-123-test.log",
  "reproduction_steps": "Describe the controlled input, setup and repeatable test.",
  "observed_impact": "Describe the actual observed unauthorized security impact."
}
```

Use the real commit and artifact. Artifact identity must equal the finding's
image if present, otherwise its file path, otherwise its package. The reference
must point to retained proof; the API validates the attestation fields and identity,
not the contents of an external proof file. Reproduce safely in an isolated test
copy, record an owner and evidence, then use the existing Kali operator command:

```bash
python3 scripts/review_finding.py 123 confirmed --owner 'Reviewer name' --version 0 \
  --evidence-file /private/evidence.txt --details-file /private/reproduction.json
```

No AI confidence percentage, CVSS threshold, scanner agreement or package-version
match can replace this evidence. Code-quality warnings cannot be confirmed as
security vulnerabilities. This gate does not automatically run exploits and cannot
make reviewer attestations infallible. Findings that cannot yet be reproduced stay
unverified for investigation; retain them to avoid silently losing coverage.

The AI queue returns `awaiting_verification` without reserving a task when no
eligible evidence-confirmed Python SAST records exist. After confirmation, an
authenticated operator may call the existing `POST /api/scans/{id}/fix` endpoint.
Worker selection repeats the gate, PR conversations include evidence-confirmed
records, and a changed file does not mark its neighboring unverified alerts as
proposed fixes. High/critical notifications use the same evidence gate. No actual
notification is sent as part of verification tests.
