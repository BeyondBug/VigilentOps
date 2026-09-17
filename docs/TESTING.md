# Testing

## Static checks

```bash
python3 - <<'PY'
import ast
from pathlib import Path
for root in ("ai-engine", "cve-intel", "wazuh-proxy", "monitoring"):
    for path in Path(root).rglob("*.py"):
        ast.parse(path.read_text(), filename=str(path))
print("Python syntax OK")
PY
python3 -m unittest discover -s tests -v
bash -n scripts/setup-kali.sh monitoring/wazuh/*.sh
docker compose config -q
```

Build the dashboard and service images:

```bash
docker compose build dashboard orchestrator celery-worker cve-intel wazuh-proxy
```

## OSV smoke test

```bash
mkdir -p reports
docker run --rm \
  -v "$PWD":/src:ro \
  -v "$PWD/reports":/reports \
  ghcr.io/google/osv-scanner:v2.4.0 \
  scan source --recursive --format sarif \
  --output-file /reports/osv.sarif /src
python3 -m json.tool reports/osv.sarif >/dev/null
```

In Jenkins, verify `OSV SCA`, `Upload Reports`, and `CVE Enrichment`. The console
must show `OSV OK`, `Uploading osv`, and HTTP 200.

## Database verification

```sql
SELECT scanner, finding_class, severity, COUNT(*)
FROM findings
WHERE scan_run_id = (SELECT MAX(id) FROM scan_runs)
GROUP BY 1,2,3 ORDER BY 1,3;
```

OSV rows should use `scanner='osv'`, `finding_class='sca'`, and exact advisory IDs.

## Gemini smoke test

Recreate containers after changing `.env`, because a restart does not reload the
environment. Confirm only non-secret values with `printenv MODEL_1` and make a
small chat-completions request. Both ordinary OpenAI-shaped objects and Gemini's
one-element array responses are supported.
