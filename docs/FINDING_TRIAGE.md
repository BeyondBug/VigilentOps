# Finding triage and lab acceptance

Use this policy with the private export from
[Testing](TESTING.md#database-verification). Scanner records are evidence to
review, not a count of distinct exploitable vulnerabilities. The export
groups by advisory/rule and path as a starting point; confirm affected package,
version, container image, and exploit conditions before merging records.

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
