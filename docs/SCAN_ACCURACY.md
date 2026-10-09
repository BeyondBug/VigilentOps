# Scan accuracy and Docker build coverage

The product branch adds two complementary gates: labeled rule detection tests
and a report inventory for every declared or discovered Docker build artifact.
Neither gate establishes that a vulnerability is exploitable. Confirmed-only
views still require reviewer evidence tied to the tested commit and artifact.

## Rule benchmark

`scanners/benchmarks/injection/cases.json` labels positive and negative examples
for four custom injection rules. Fixtures are scanned as source and never run.
The runner records TP, FP, TN, FN, precision, recall, false-positive rate,
per-rule counts, mismatches, unrelated alerts, scanner image ID, and rule/fixture
hashes. Execution or parser errors invalidate scoring. Undefined ratios are null.
Duplicate alerts for one labeled case count once.

Run on Kali, with the selected scanner image already available:

```bash
python3 scripts/benchmark_semgrep.py \
  --rules scanners/semgrep-rules --fixtures scanners/benchmarks/injection \
  --host-rules "$PWD/scanners/semgrep-rules" \
  --host-fixtures "$PWD/scanners/benchmarks/injection" \
  --image semgrep/semgrep:1.178.0 \
  --output reports/rule-benchmark.json --require-pass
```

Jenkins runs this gate before scanning targets and reuses its resolved Semgrep
image ID. The benchmark covers these labeled rule cases only, not every rule,
ecosystem, application, or exploit. Existing `--config=auto` registry rules remain
additional, unbenchmarked coverage; their downloaded content is not pinned by
this benchmark. A perfect fixture score must not be advertised as production
accuracy. Add independent holdout examples and reviewed production dispositions
before estimating production precision or recall.

Four custom rules exclude fixed strings from SQL concatenation, shell execution,
eval/Function, and innerHTML alerts. Dynamic expressions remain review candidates.
Fixed commands can still have dangerous behavior, and fixed markup or code may
have other defects; these exclusions concern input injection, not overall safety.

## Docker build inventory

Optional `.secureguard/artifacts.json` schema:

```json
{"schema":1,"artifacts":[
  {"id":"api","context":".","dockerfile":"api/Dockerfile",
   "target":"production","services":["api","worker"]}
]}
```

IDs must be unique. Paths must exist within the repository, without traversal or
symlinks. Each discovered `Dockerfile`, `Dockerfile.*`, or `*.Dockerfile` must appear
in the manifest. Dependency/cache directories are excluded. Multiple targets or
contexts can map to one Dockerfile. Without a manifest, each Dockerfile's parent
is the inferred context; projects requiring a root context must declare it.
Unsupported contexts fail explicitly rather than silently skipping the build.

The adapter builds each artifact under a unique temporary tag, resolves immutable
image IDs, deduplicates identical built images, and scans every unique image with
Trivy and Dockle. Merged SARIF retains image IDs and artifact mappings. Coverage
records scanner image IDs, Trivy database metadata, per-image accepted receipts,
result counts, and build statuses in `reports/artifacts/coverage.json`.

A failed build, missing report, failed scanner, missing image, mismatched identity,
or inconsistent result count fails validation. Zero results require actual accepted
reports. A repository with no Docker build artifacts is explicitly not applicable.
Old output is cleared before scanner execution. Jenkins requires this inventory,
retains its JSON/SARIF privately, and cleans labeled scan containers on cancellation.

This inventory covers repository Docker builds. It does not claim coverage of
third-party runtime images, Compose-only services, every dependency, every possible
build argument, or all dynamically selected stages. Jenkins retains aggregate
accepted tool receipts; per-artifact coverage is in its restricted build artifacts.
The adapter uses the existing Docker daemon, including its socket for image scans;
resource limits do not make it a safe sandbox for untrusted Dockerfiles.

## Acceptance

Run `python -m unittest discover -s tests -v` in the candidate API image on Kali.
Run the real scanner benchmark with `--require-pass`, then a controlled fixture
with multiple unique images and duplicate build identities. Confirm both merged
reports validate, and separately prove a failed build cannot produce complete
coverage. Validate the Jenkinsfile with Jenkins' model-validation endpoint before
any build is authorized. A Gitea push can trigger Jenkins and needs user approval.
