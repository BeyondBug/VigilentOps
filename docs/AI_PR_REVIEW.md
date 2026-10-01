# Reviewing AI-generated pull requests

The AI worker opens `WIP:` Gitea pull requests as proposals. It may change a whole Python file for several findings at once. A syntax check or a successful Jenkins build on the **base commit** is not evidence that the PR branch works.

## Review sequence

1. Record the PR head commit, base commit, changed files, and scan ID. Confirm the PR conversation contains every numbered tool-finding part promised in its body, then match each changed file to the relevant findings. The conversation covers the whole scan, while the code proposal covers only selected Python SAST findings. Confirm the branch is based on the expected repository and commit.
2. Read the entire diff, including surrounding call sites, environment variables, Docker Compose settings, and clients of the changed service. Check for altered network binds, TLS behavior, authentication, file paths, permissions, and cleanup.
3. For each finding, explain how the patch removes the cause. A renamed variable, a comment, or a different temporary path alone may leave the issue intact. Check that hardcoded credentials, insecure transport, or unsafe subprocess calls were actually removed where relevant.
4. Pull the **PR head branch** on the lab server and run the affected checks there. Follow [Testing](TESTING.md). Run a new scan of that branch when practical; compare the original finding and any new findings. Treat scanner silence as one signal, not proof of correctness.
5. Verify the changed service through its real clients. For example, a Wazuh proxy change must allow Grafana to connect over the Compose network and must work with the manager's certificate setup.
6. Only after review and server validation, mark the PR ready, approve, and merge. If the proposal is unsafe, leave it in draft while correcting it or close it with a clear reason. Keep unverified findings open for follow-up.

## Current review example

PR #15 from scan #229 illustrates why the branch needs its own review. Its proposed Wazuh proxy loopback bind would prevent Grafana from reaching the proxy over Docker networking. Enabling certificate verification without a trusted CA fails against the lab's self-signed Wazuh certificate. Other proposed changes leave some hardcoded credentials and insecure HTTP behavior. Jenkins #302 ran on the base branch before that PR existed, so its success does not validate PR #15. Review these facts against the current PR state before taking action; this example is a snapshot, not a release status.

## Prepared review mode and current rejection

The shared pipeline now accepts administrator-only `REVIEW_AI_PR` parameters
for the exact PR head. See [Next server session](NEXT_SERVER_SESSION.md).
Normal hooks do not accept AI branch names, and review mode skips another AI
task. Candidate interface/Bandit checks improve proposals but do not replace
this review sequence.

On 30 September, PR #18's B107/B310 findings survived the targeted rescan.
Do not merge that unchanged proposal. Correct or reject it explicitly and
verify a new real candidate against its head, including real service clients.

On 1 October, the unchanged PR #18 was explicitly rejected and closed without
merging; its five proposal records were reopened. New sg-bench PR #1 covered
all 179 scan findings in 11 parts and passed exact-head Jenkins #363, but its
pickle-to-JSON and plain SHA-256 password changes failed review. That PR was
also closed, reopening 16 proposal records. This is evidence that a successful
scan and preserved signatures do not prove a safe fix. See
[the dated review record](ACCEPTANCE_2026-10-01.md).
