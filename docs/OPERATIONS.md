# Lab operations and recovery

Use this guide on the Linux lab server. Commands below are **not** evidence
that a backup, restore, rotation, or alert route has been verified. Record
those outcomes in [the server acceptance record](SERVER_ACCEPTANCE.md).

## Backup before deployment

Keep backups outside the Git checkout and limit access to the server operator.
Record the Compose project name and actual volume names first:

```bash
cd ~/secureguard
docker compose ls
docker volume ls --format '{{.Name}}'
```

Capture the PostgreSQL schema and data through `pg_dump` using credentials
already inside the container. Save to an operator-controlled directory; do
not commit the dump:

```bash
mkdir -p ~/secureguard-backups
chmod 700 ~/secureguard-backups
docker exec sg-postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > ~/secureguard-backups/postgres-before-release.dump
chmod 600 ~/secureguard-backups/postgres-before-release.dump
```

For Gitea, Jenkins, and Grafana, stop writers during the volume snapshot.
Inspect each actual volume with `docker volume inspect`; mount it read-only
into a temporary backup container and archive its contents to the protected
backup directory. Record the exact volume name, archive name, size, and date.
Do not copy PostgreSQL's live data files as a substitute for `pg_dump`.

## Prove recovery

Restore a copy into an **isolated** Compose project or host, never over the
live lab as a first test. Restore the database dump with `pg_restore` into an
empty compatible PostgreSQL database, then restore the Gitea/Jenkins/Grafana
archives into separate test volumes. Start the isolated stack and confirm:

- Gitea repositories, users, and webhook configuration are visible.
- Jenkins jobs and credentials can be accessed by authorized operators.
- Grafana dashboards and data sources load.
- The orchestrator can read prior scans and create a new scan.

Record recovery time, missing data, and the operator who performed the test.
Set a backup retention and off-host copy schedule according to the lab's
storage and recovery requirements. A file existing on the same host is not
a tested recovery plan.

## Ownership and response

Fill this table with real people or team names and a working contact route
before exposing the system beyond the lab:

| Event | Owner | Alert route | First action |
| --- | --- | --- | --- |
| Jenkins scan failed or missing required report | To assign | To configure | Inspect failed stage and preserve build ID |
| Orchestrator, PostgreSQL, Redis, or CVE service unavailable | To assign | To configure | Check Compose status and recent logs |
| New critical/high or secret finding | To assign | To configure | Triage affected artifact; revoke active secrets |
| AI task failed, partial PR conversation, or review pending | To assign | To configure | Check worker task and PR head; keep finding open |
| Backup failed or restore test failed | To assign | To configure | Repair backup path before next deployment |

Verify an actual notification reaches the named owner. The `Notify` stage
alone does not prove an alert was delivered.

## Scanner and credential maintenance

The Jenkinsfile still uses several `:latest` scanner images. Pin each to a
tested version or digest **after** the acceptance scan establishes which
versions work on the server. Keep a small inventory of image, version/digest,
date, and report format; update one scanner at a time and rerun the report
contract. Set a regular review cadence and record accepted vulnerability
exceptions with owner and review date.

Rotate historical or exposed credentials, including the Grafana password
requested earlier. Follow [webhook token rotation](WEBHOOK_TOKEN_ROTATION.md)
for the shared Jenkins trigger. Review access to old Git history and Jenkins
logs. Restrict published management ports with server firewall rules or a
trusted-network bind; verify the dashboard and Grafana remain reachable from
intended clients and that APIs require the intended authentication. Review
Docker socket mounts and privileged monitoring services before production
exposure.
