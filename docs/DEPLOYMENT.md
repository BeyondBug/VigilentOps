# Deployment

Run the commands in this guide on the Linux lab server, not on the development
device. For the service map and scan flow, see [Architecture](ARCHITECTURE.md).

## Prerequisites

- Docker Engine with Compose v2
- A Linux host capable of running Falco and Wazuh
- Git, curl, Python 3 and OpenSSL
- A Gitea personal access token for the remediation bot

## Configure

Create the local configuration and replace every placeholder:

```bash
cp .env.example .env
chmod 600 .env
```

Generate the shared API key with `openssl rand -hex 32`. Configure the same
`SG_API_KEY` in `.env`; Compose passes it to Jenkins, the orchestrator, and the
Celery worker. Never commit `.env`.

Existing lab installations store Gitea tables in `secureguard`, so
`GITEA_DB_NAME=secureguard` is the compatibility default. A new installation may
use a separate database only after creating it and migrating Gitea deliberately.

For a configured OpenAI-compatible remediation endpoint, set the matching
`MODEL_n`, `API_KEY_n`, and `API_URL_n` values in `.env`. For example:

```dotenv
MODEL_1=<supported-model-id>
API_KEY_1=<secret>
API_URL_1=<provider-chat-completions-url>
```

Source files selected for remediation are sent to the configured model provider.
Leave **all** `API_KEY_n` values empty if repository data must not leave the
lab. In that case, the AI worker
skips proposal generation.
`AI_WORKER_CONCURRENCY` defaults to 1 for the lab. See
[AI rate limits and patch quality](AI_RATE_LIMITS_AND_QUALITY.md) before
increasing it or trusting a proposed patch.

## Start and verify

Prepare the HTTPS gateway on Kali before starting Compose:

```bash
python3 scripts/configure_gateway.py --public-url https://SERVER-IP:3000
python3 scripts/prepare_jenkins_security.py
```

Existing installations must also migrate Jenkins URLs and Gitea hooks using
[Gateway setup](GATEWAY.md).

```bash
docker compose config -q
docker compose up -d --build
docker compose ps
docker compose exec -T orchestrator python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/health').status)"
docker compose exec -T cve-intel python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8001/health').status)"
```

Open the dashboard at `https://<lab-host>:3000/dashboard/` using the private
gateway login. Browser API requests share that HTTPS origin; their upstream
services remain on the internal Compose network.

The optional Gitea Actions runner is disabled by default because it requires a
registration token and access to the Docker socket. Start it only when needed:

```bash
docker compose --profile actions up -d gitea-runner
```

Jenkins and the monitoring stack are optional. Enable the profiles needed on
this server:

```bash
docker compose --profile ci up -d jenkins
```

Start Wazuh before its proxy so the manager can generate its API certificate
and security database in the persistent `wazuh_api_config` volume:

```bash
docker compose --profile monitoring up -d wazuh
docker compose --profile monitoring up -d
```

For an existing installation, back up `/var/ossec/api/configuration` from the
running `sg-wazuh` container and copy it into the new
`secureguard_wazuh_api_config` volume **before** recreating Wazuh. This
preserves the API certificate and user password. Docker copies files to the
host with the invoking user's ownership by default; after loading the volume,
restore ownership to `wazuh:wazuh` inside the container. Keep the private key
and RBAC database unreadable by other users. Permit the proxy to traverse the
configuration and `ssl` directories and read `ssl/server.crt` (mode 0644).
The proxy mounts that volume
read-only, trusts its self-signed certificate, and limits unauthenticated
routes to read-only `/sca/` requests. Set `WAZUH_PASSWORD` in `.env` to the
actual Wazuh API password. Rotate the default API password on a new install.
The bundled certificate has only `localhost` in its DNS names, so the proxy
checks the pinned certificate without a hostname check when connecting to
`sg-wazuh`. For full hostname validation, issue a certificate with `sg-wazuh`
in its SAN.

Wazuh alerts are retained in the `wazuh_alerts` volume and mounted read-only
in Promtail. During an existing-install migration, copy any previous
`/var/ossec/logs/alerts` contents into that volume before recreating Wazuh.
Wazuh's entrypoint creates its archive and firewall log directories before
the manager starts; without them, analysisd fails and SCA endpoints return
errors. Check `docker exec sg-wazuh /var/ossec/bin/wazuh-control status`,
`docker exec sg-promtail ls /var/ossec/logs/alerts`, and the proxy
`/_proxy_health` route after a redeploy.

`docker compose --profile monitoring up -d` starts the base services as well
as monitoring services. Grafana is available through HTTPS 3000 at `/grafana/`.
Prepare gateway TLS and authentication before starting the stack, following
[Gateway setup](GATEWAY.md); only the gateway publishes a host port. The Wazuh proxy
listens on port 8002 inside the Compose network; it is not published to the
host. Grafana uses `http://sg-wazuh-proxy:8002`, so the proxy must listen on
the container network interface.

The `migrate` service applies numbered SQL files from `ai-engine/migrations/`
before the API, worker, and CVE service start. It also upgrades existing
PostgreSQL volumes without removing their data. Back up the database before
pulling changes that include a new migration.

The orchestrator, Celery worker, and CVE service must have clean startup logs:

```bash
docker compose logs --tail=100 orchestrator celery-worker cve-intel
```

## Gitea compatibility and recovery

Never delete `postgres_data` or `gitea_data` to fix a login problem. Confirm the
configured database and inspect existing users first:

```bash
docker exec sg-postgres psql -U "$POSTGRES_USER" -d secureguard \
  -c 'SELECT id,name,email,is_admin,is_active FROM "user";'
```

Back up PostgreSQL before changing `GITEA_DB_NAME`.

## Jenkins

The pipeline reads `jenkins/pipelines/Jenkinsfile`. Configure a Jenkins credential
named `gitea-cred`, then configure a Gitea push webhook for the Generic Webhook
Trigger. The pipeline accepts `main`, `develop`, and `master`. Set
`JENKINS_HOME_HOST` in `.env` to the host mountpoint of the `jenkins_data` Docker
volume (the path returned by `docker volume inspect`). Scanner containers use
this path to mount the Jenkins workspace. Start Jenkins with the `ci` profile
after setting it.

The job uses Secret text credential ID `gitea-webhook-token`. Server preparation
generates it privately; Jenkins bootstrap enables a private realm, an
administrator permission and a separate read/metrics account, plus CSRF.
Gateway Basic authentication is forwarded to the matching native administrator.
The public trigger path remains blocked; Gitea hooks call the internal prefixed
endpoint. Follow [Next server session](NEXT_SERVER_SESSION.md) for existing
installations: first apply the new trigger through one pipeline run, then
update hooks. An accepted-branch push uses `main`, `develop` or `master`.
Administrator-only `REVIEW_AI_PR` parameters allow an exact AI PR-head scan
without starting another AI task; a base-branch build does not cover that head.
The pipeline now checks the cloned target's commit against the webhook commit
before registering a scan. A branch that moves before checkout must be
triggered again. For production exposure, follow the coordinated
[webhook token rotation](WEBHOOK_TOKEN_ROTATION.md) procedure.

OSV-Scanner is pinned to `v2.4.0`. It scans supported manifests and lockfiles,
writes `osv.sarif`, and uploads that report to the orchestrator.

Dependency-Check needs a populated NVD data cache. Its first scan downloads
vulnerability data into the persistent `depcheck-cache` Docker volume and can
take substantially longer than later scans. The Jenkins stage now allows the
update and fails if it cannot produce a SARIF report. Ensure the server can
reach the [required remote data sources](https://dependency-check.github.io/DependencyCheck/data/index.html)
before expecting that stage to pass.
If the private server `.env` has a valid `NVD_API_KEY`, Compose passes it to
Jenkins for Dependency-Check. A key helps with NVD API limits; it does not
repair DNS or blocked outbound HTTPS. The Jenkins stage writes a temporary
mode-0600 properties file owned by the Dependency-Check container user,
mounts it for Dependency-Check, and removes it at
stage exit. This keeps the key out of command arguments and console output.
If the Dependency-Check container cannot resolve NVD, CISA, or RetireJS hosts
while the server can, set `SCANNER_DNS` in the server's private `.env` to an
IP address of a resolver reachable from Docker's bridge network, then recreate
Jenkins. The setting adds `--dns` only to Dependency-Check's container; leave
it empty when Docker's default resolver works. On the Kali lab host on
30 September 2026, the host resolver was `10.20.16.1` while Docker was
configured with public resolvers; Jenkins #317 failed with DNS lookup errors.
Verify the chosen resolver inside a disposable scanner container before using
it for the next full scan.
When the NVD REST API repeatedly fails during the first cache fill, an
ODC-compatible datafeed can be set through `NVD_DATAFEED_URL` in the private
server `.env`, followed by a Jenkins recreate. For example, Dependency-Check
documents its own best-effort daily mirror as
`https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/nvdcve-{0}.json.gz`.
The feed downloader uses more bandwidth than the API, and the mirror can lag
when its upstream NVD update fails. Check feed freshness and the completed
SARIF report before accepting a scan. See the
[official mirror documentation](https://dependency-check.github.io/DependencyCheck/data/mirrornvd.html).
Grype now keeps its vulnerability database in the persistent `grype-cache`
volume and bounds its update waits. The first cache fill still needs access
to Anchore's database service.
Jenkins updates Trivy's persistent `trivy-cache` once before the parallel
scanners start, trying the official Docker Hub, ECR, and GHCR database
locations in that order ([Trivy DB documentation](https://trivy.dev/docs/dev/configuration/db/)).
Both Trivy stages read that cache; a failed update
stops the scan instead of producing a report from missing data.

The shared Jenkins job accepts clone URLs only from `http://sg-gitea:3000`
with a single owner and repository path. Each run removes generated reports
from the reused Jenkins workspace before scanning, so an earlier report cannot
satisfy the next run's report validator.

Snyk is optional. Set `SNYK_TOKEN` in the server's private `.env` and recreate
the Jenkins container to enable it; an unset token skips the stage. Keep the
token out of Git and Jenkins console logs.

The shared pipeline validates required scanner reports with
`scripts/validate_scan_reports.py` before uploading them. Semgrep, Gitleaks,
Trivy dependency, Grype, OSV, Dependency-Check, and Syft reports are always
required; Bandit is required for Python targets. The target image build and
its Dockle/Trivy scans run in one stage so the scans cannot start before the
image exists. If the target image builds, both image SARIF reports are required.
Dockle container-configuration results are parsed as `iac` findings and appear
in the dashboard and any AI PR finding conversation for that scan.
Generic image building may fail for repositories that need custom build
arguments; in that case the image scans are skipped and the console warns.

## Security notes

- Rotate all credentials that were ever committed to Git history.
- The old one-off Grafana and Wazuh panel scripts were removed. Grafana now
  provisions `monitoring/grafana/dashboards/secureguard-main.json`, and
  Promtail ships Wazuh alerts to Loki.
- Restrict the HTTPS gateway on port 3000 to intended clients. Other Compose
  services have no published ports. Host SSH is managed separately.
- The Wazuh proxy is internal-only; access it through an authenticated frontend
  or a temporary SSH tunnel when troubleshooting.
- Docker socket access grants host-equivalent privileges. It remains limited to
  services that launch scanner containers.
- AI-created branches are not force-pushed and must be reviewed before merging.
- See [AI pull request review](AI_PR_REVIEW.md) for the PR validation sequence.
