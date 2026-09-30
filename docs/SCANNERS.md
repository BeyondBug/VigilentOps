# Scanner coverage

The shared pipeline comes from `VigilentOps/main`. New offline changes need
deployment and verification on Kali; this document describes intended code
behavior, not successful live coverage. Do not run scanners on the laptop.

| Tool | Purpose | Report | Requirement |
| --- | --- | --- | --- |
| Semgrep | Source security rules, including shared lab rules | SARIF | Always |
| Bandit | Python security checks | JSON | Python files present |
| Gitleaks | Potential secrets | SARIF | Always |
| Trivy dependencies | Source dependency vulnerabilities/secrets | SARIF | Always |
| Grype | Source dependency vulnerabilities | SARIF | Always |
| OSV-Scanner | Supported package/advisory matching | SARIF | Always; explicit no-package coverage allowed |
| Dependency-Check | Dependency/advisory matching | SARIF | Always |
| Syft | Package inventory | SPDX JSON | Always; inventory does not create vulnerability findings |
| Hadolint | Dockerfile instructions and embedded shell lint | Converted SARIF | Always; explicit no-file coverage allowed |
| ShellCheck | Shell diagnostics | Converted SARIF | Always; explicit no-file coverage allowed |
| Checkov | Infrastructure configuration | SARIF | Optional under the current contract |
| Snyk | Dependency checks | SARIF | Required when its private token is configured |
| Trivy image | Built image vulnerabilities | SARIF | Required after a successful target image build |
| Dockle | Built container configuration | SARIF | Required after a successful target image build |

An accepted report with zero results is different from an absent report.
`not_applicable` states the tool found no supported input; it does not prove
the repository has no vulnerabilities. The API retains each accepted report
receipt, digest, result count and coverage; new scans cannot complete without
their declared required reports. Historical scans do not gain new coverage
retroactively. Optional and skipped image scans must be stated in acceptance.

## Added static linters

The adapter [run_static_scans.py](../scripts/run_static_scans.py) uses
`hadolint/hadolint:v2.15.1-debian` and `koalaman/shellcheck:v0.11.0`.
These are version tags; record deployed image digests during acceptance and
maintain them with the other scanner versions. See the official
[Hadolint documentation](https://github.com/hadolint/hadolint/blob/master/README.md)
and [ShellCheck 0.11.0 manual](https://github.com/koalaman/shellcheck/blob/v0.11.0/shellcheck.1.md).

Discovery includes nested `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, shell
suffixes `.sh`, `.bash`, `.dash`, `.ksh`, `.bats`, and files with supported shell
shebangs. It skips symlinks and `.git`, `.venv`, `venv`, `node_modules`, `.tox`,
and `__pycache__` directories. Nonstandard filenames without a supported
suffix/shebang need an explicit policy change; this is not all-language lint.
File counts and exclusions are recorded in each report.

Hadolint uses the shared `scanners/static-analysis/hadolint.yaml` policy and
disables inline ignore pragmas. ShellCheck ignores repository rc files;
inline ShellCheck directives remain supported and require review. External
sourced files are not followed with `--external-sources`; files supplied in
the same batch may still be analyzed together. Generic POSIX/bash/dash/ksh
analysis does not establish runtime correctness for other shells.

Containers have read-only source mounts, no network, dropped capabilities,
no new privileges and bounded CPU, memory and process counts. Batches contain
at most 100 files with a ten-minute timeout; the combined stage has a
20-minute timeout. Native exit 0/1 with valid JSON is accepted; exit 1 needs
reported diagnostics. Other exit codes, malformed output and timeouts fail.
Adapter and Jenkins post cleanup remove child containers for the current build.
Images must be available from the server's Docker registry access; no
network inside a scanner does not prevent the Docker daemon from pulling one.

Stored class is `quality`: native errors map to MEDIUM, warnings to LOW and
info/style to INFO. These diagnostics carry no inferred CVE or CVSS claim.
Parser diagnostics that may quote source tokens are redacted in PR comments;
review their details in the restricted scanner report.
All stored findings appear in future whole-scan AI PR conversations. The AI
worker does not automatically patch these files: its current scope is eligible
Python SAST. The Grafana scanner chart includes every scanner label; receipt
coverage must still be inspected separately when a tool reports zero results.

## Deployment and acceptance

Drain existing queues, take a private backup, rebuild Jenkins for its Python 3
adapter, and deploy the API/shared Jenkinsfile together. The expanded contract
requires both new reports for new scans; older running pipeline versions may
otherwise fail registration. Pre-pull images on Kali, run the expanded suite,
then verify real clean, diagnostic and no-file targets. Confirm API paths,
rule IDs, severity, receipts, PR comments and rendered Grafana/UI behavior.
See [Next server session](NEXT_SERVER_SESSION.md) and [Testing](TESTING.md).

Dependency scanners still require trustworthy database/cache updates and
outbound connectivity. Falco and Wazuh are runtime monitoring components,
not substitutes for repository scans. Adding linters does not resolve the
five pending repository reruns, AI PR #18, dependency triage or restore drill.
