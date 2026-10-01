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
