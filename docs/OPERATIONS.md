# Lab operations and recovery

Use this guide on the Linux lab server. Commands below are **not** evidence
that a backup, restore, rotation, or alert route has been verified. Record
those outcomes in [the server acceptance record](SERVER_ACCEPTANCE.md).

## Backup before deployment

Keep backups outside the Git checkout and limit access to the server operator.
Include the private `.env` and `secrets/gateway/` TLS/login files in an encrypted
or access-restricted configuration backup. Only distribute the public
`ca.pem`; never publish the CA/server private keys or password file. See
[gateway recovery](GATEWAY.md) before changing public service URLs or ports.
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

For Gitea, Jenkins, Grafana, Prometheus, `wazuh_alerts`, and
`wazuh_api_config`, stop writers during the volume snapshot.
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
- Prometheus targets and Wazuh SCA/alert panels load; preserve Wazuh API
  certificate, private key, RBAC database, and log volume permissions.
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

The shared pipeline reads versioned scanner references from
`scanners/images.json`; Hadolint and ShellCheck are also versioned. All 11
selected images were pulled on Kali and report compatibility was exercised
in completed scans. Version tags can remain mutable; maintain digest pins
after compatibility review. Keep an inventory of image, version/digest,
date, and report format; update one scanner at a time and rerun the report
contract. Set a regular review cadence and record accepted vulnerability
exceptions with owner and review date.

Rotate historical or exposed credentials, including the Grafana password
requested earlier. Follow [webhook token rotation](WEBHOOK_TOKEN_ROTATION.md)
for the shared Jenkins trigger. Review access to old Git history and Jenkins
logs. Rotate the NVD API key used by the 26 September acceptance run: its
command argument appeared in a server process inspection before the pipeline
switched to a temporary properties file. Restrict published management ports
with server firewall rules or a trusted-network bind. Verify the dashboard
and Grafana remain reachable from intended clients and that APIs require the
intended authentication. Review Docker socket mounts and privileged monitoring
services before production
exposure. Native Jenkins authentication, limited metrics permissions, CSRF
and credential-backed hooks passed live checks on 1 October. See
[the acceptance record](ACCEPTANCE_2026-10-01.md).

Maintain Jenkins core, Java and plugin pins together using
[Jenkins upgrades](JENKINS_UPGRADES.md). The 1 October upgrade retained a
private idle-controller snapshot at
`~/secureguard-backups/pre-jenkins-upgrade-20261001-121746` and the old image;
an isolated restored-volume rehearsal passed before deployment. An older core
must use restored pre-upgrade state, not the upgraded live plugin directory.

## Prepared backup and isolated restore automation

Run on Kali from the checkout with the full lab containers present:

```bash
python3 scripts/backup_lab.py
python3 scripts/restore_lab_backup.py /absolute/path/to/the/printed/backup
python3 scripts/verify_restored_services.py /absolute/path/to/the/printed/backup \
  --output reports/restored-service-access.json
```

The backup command refuses known running/queued Jenkins work or active,
reserved/deferred Celery tasks. It stops persistent writers, dumps PostgreSQL,
archives Gitea/Jenkins/Grafana/Prometheus/Wazuh/Loki/Redis volumes and private configuration,
records checksums, image IDs and table counts, then restarts the prior running
writers. Expect a maintenance interruption; verify service health afterward.
It requires the CI/monitoring containers to exist and is not a partial-stack
backup command. It requires Gitea and findings to share the configured database;
separate databases require an explicit additional backup procedure. New
directories are private and existing snapshots are never
overwritten. Preserve the recorded PostgreSQL and archive image IDs locally.

The restore command creates unique disposable volumes and a database with no
network or published ports. It restores the dump, compares public table counts
and restores/compares each archived volume. It cleans up only its own named
resources. It does not change live volumes. Check private configuration
recovery separately; full restored service login/client validation remains
required. On 1 October, the new consistent snapshot and isolated restore
passed: 122 public table counts and eight volume archives matched. This
evidence does not cover restored service login/access. Existing historical
backups use different manifests; do not run this
restore command against them without an explicit conversion/review.

Restore preflight now requires checksums for the database, private configuration
and every distinct volume archive, exact image IDs and table counts before
creating Docker resources. Missing, corrupt or symlinked artifacts are rejected.
Backup output must be outside the checkout. Use a quiet maintenance window:
prevent new pushes, API writes and scheduled jobs while taking the snapshot.
Idle checks are point-in-time checks; they do not lock out other operators.

The service-access command requires a new manifest with per-service volume
mounts and image IDs. It restores PostgreSQL and Gitea/Jenkins/Grafana into
unique disposable volumes on a Docker internal network, with no published
ports or Docker socket. Restored Jenkins has zero executors and stays quiet;
outbound deliveries cannot reach the live stack. Snapshot credentials are
read privately; failures retain restricted diagnostics before cleanup.
Grafana's two explicit configuration mounts are readable by its unprivileged
process, while their enclosing host temporary directory remains private.

On 1 October, `lab-20261001-114129` passed both drills: 123 public table counts,
eight archive comparisons, 13 restored Gitea repositories, one Grafana
dashboard and one Jenkins job. Native authentication succeeded and anonymous
Jenkins access was denied. Disposable resources were removed and live
writers/workers resumed. This verifies core service access; it does not
verify every application workflow or all restored Grafana datasource queries.
