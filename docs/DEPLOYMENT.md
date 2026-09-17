# Deployment

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

For temporary Gemini remediation:

```dotenv
MODEL_1=gemini-3.6-flash
API_KEY_1=<secret>
API_URL_1=https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
```

Source files selected for remediation are sent to the configured model provider.
Disable AI remediation when repository data must not leave the lab.

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

The pipeline reads `jenkins/pipelines/Jenkinsfile`. Configure Jenkins credentials
named `gitea-cred` and `sonar-token`, then configure a Gitea push webhook for the
Generic Webhook Trigger. The pipeline accepts `main`, `develop`, and `master`.

OSV-Scanner is pinned to `v2.4.0`. It scans supported manifests and lockfiles,
writes `osv.sarif`, and uploads that report to the orchestrator.

## Security notes

- Rotate all credentials that were ever committed to Git history.
- Restrict exposed ports 3000, 8000, 8001, 8081, 9090, and 3002 with a firewall.
- The Wazuh proxy is internal-only; access it through an authenticated frontend
  or a temporary SSH tunnel when troubleshooting.
- Docker socket access grants host-equivalent privileges. It remains limited to
  services that launch scanner containers.
- AI-created branches are not force-pushed and must be reviewed before merging.
