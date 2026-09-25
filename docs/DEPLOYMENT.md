# Deployment

Run the commands in this guide on the Linux lab server, not on the development
device. For the service map and scan flow, see [Architecture](ARCHITECTURE.md).

## Prerequisites

- Docker Engine with Compose v2
- A Linux host capable of running Falco and Wazuh
- Git and curl
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
lab; replace the example placeholder values too. In that case, the AI worker
skips proposal generation.

## Start and verify

```bash
docker compose config -q
docker compose up -d --build
docker compose ps
curl -fsS http://localhost:8000/health
curl -fsS http://localhost:8001/health
```

Open the dashboard at `http://<lab-host>:3001`. Its Nginx server proxies API
requests over the internal Compose network, so remote browsers do not need to
reach `localhost:8000` or `localhost:8001`.

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

Prepare Wazuh's API certificate before starting the proxy:

```bash
docker compose --profile monitoring up -d wazuh
mkdir -p monitoring/wazuh/certs
docker cp sg-wazuh:/var/ossec/api/configuration/ssl/server.crt monitoring/wazuh/certs/api.crt
chmod 644 monitoring/wazuh/certs/api.crt
docker compose --profile monitoring up -d
```

The certificate is specific to this Wazuh instance and is excluded from Git.
Repeat the copy after replacing the manager's certificate, then recreate the
proxy. Set `WAZUH_PASSWORD` in `.env` to the actual Wazuh API password before
starting the proxy; the placeholder is not a valid password. Rotate the
manager's default API password if this is a new installation. The proxy trusts
the copied self-signed certificate, checks the certificate chain, and limits
unauthenticated proxy routes to read-only `/sca/` requests. The bundled
certificate has only `localhost` in its DNS names, so the proxy pins that
certificate without a hostname check when connecting to `sg-wazuh`. For full
hostname validation, issue a certificate with `sg-wazuh` in its SAN.

`docker compose --profile monitoring up -d` starts the base services as well
as monitoring services. Grafana is published on port 3002. The Wazuh proxy
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

The job's webhook token in the Jenkinsfile is `secureguard-webhook-token`.
Give the job access to `gitea-cred` and configure the Gitea webhook to call
the Jenkins Generic Webhook Trigger endpoint. A push to a branch outside
`main`, `develop`, or `master` does not match the pipeline trigger. To
validate an AI PR branch, explicitly run a scan against that branch on the
server; a preceding main-branch build does not cover it.
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

Snyk is optional. Set `SNYK_TOKEN` in the server's private `.env` and recreate
the Jenkins container to enable it; an unset token skips the stage. Keep the
token out of Git and Jenkins console logs.

The shared pipeline validates required scanner reports with
`scripts/validate_scan_reports.py` before uploading them. Semgrep, Gitleaks,
Trivy dependency, Grype, OSV, Dependency-Check, and Syft reports are always
required; Bandit is required for Python targets. The target image build and
its Dockle/Trivy scans run in one stage so the scans cannot start before the
image exists. If the target image builds, both image reports are required.
Generic image building may fail for repositories that need custom build
arguments; in that case the image scans are skipped and the console warns.

## Security notes

- Rotate all credentials that were ever committed to Git history.
- The old one-off Grafana and Wazuh panel scripts were removed. Grafana now
  provisions `monitoring/grafana/dashboards/secureguard-main.json`, and
  Promtail ships Wazuh alerts to Loki.
- Restrict exposed ports 3000, 8000, 8001, 8081, 9090, and 3002 with a firewall.
- The Wazuh proxy is internal-only; access it through an authenticated frontend
  or a temporary SSH tunnel when troubleshooting.
- Docker socket access grants host-equivalent privileges. It remains limited to
  services that launch scanner containers.
- AI-created branches are not force-pushed and must be reviewed before merging.
- See [AI pull request review](AI_PR_REVIEW.md) for the PR validation sequence.
