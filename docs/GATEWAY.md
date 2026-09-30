# One application port

The `gateway` service is the only Compose service with a published host port:
**HTTPS 3000**. It proxies browser requests over `sg-net`; service-to-service
calls stay on that Docker network. Host SSH is separate from the Compose stack.

| Browser path | Service | Authentication |
| --- | --- | --- |
| `/` | Gitea, repository HTTPS clone/push, Gitea API | Gitea accounts/tokens |
| `/dashboard/` | Findings dashboard | Gateway username/password |
| `/dashboard/api/` | Scan API | Gateway login; writes also require `X-API-Key` |
| `/dashboard/cve-intel/` | CVE read API | Gateway login |
| `/jenkins/` | Jenkins | Gateway username/password; Jenkins permissions also apply when configured |
| `/grafana/` | Grafana, including Live WebSockets | Grafana login/permissions |
| `/prometheus/` | Prometheus UI and query API | Gateway username/password |

Databases, Redis, Loki, Pushgateway, cAdvisor, exporters, and Wazuh's API
have no host port bindings. Grafana still reaches its data sources internally.
The public Jenkins webhook endpoint is blocked; Gitea delivers directly over
`sg-net` using its existing private trigger token. Jenkins gateway credentials
are stripped before forwarding requests. Configure Jenkins's own users and
role permissions before admitting other users to this administrative lab.
Gitea SSH port 2222 and Jenkins inbound agent port 50000 are removed; use
repository HTTPS and Jenkins WebSocket agents when needed. Wazuh agent
enrollment/event ports also stay internal. External Wazuh agents require a
separate private agent network; an HTTP proxy does not carry their protocol.

## Prepare on the server

Replace credential placeholders in `.env`, then run from the checkout:

```bash
python3 scripts/configure_gateway.py --public-url https://SERVER-IP:3000
docker compose --profile ci --profile monitoring up -d --build
```

The script creates a private lab CA, a server certificate with the server
address plus `localhost` in its SAN, and a separate gateway login. It stores
`PUBLIC_URL`, `PROXY_AUTH_USER`, and `PROXY_AUTH_PASSWORD` in the private `.env`.
Private keys and the password hash remain in ignored `secrets/gateway/`.
Only the server certificate/key and password hash are mounted into Nginx.

To view the dashboard/Jenkins/Prometheus gateway login **in your private server shell**:

```bash
sed -n '/^PROXY_AUTH_USER=/p; /^PROXY_AUTH_PASSWORD=/p' .env
```

Import **only** `secrets/gateway/ca.pem` into your client/browser trust store.
Never distribute `ca-key.pem` or `server-key.pem`. Server CLI requests use
`--cacert secrets/gateway/ca.pem`; do not disable certificate verification.
For a CA-issued certificate, install the matching full chain and key at the
gateway mount paths and keep `PUBLIC_URL` accurate.

Rerun the preparation command when the server address changes or before its
365-day certificate expires. It keeps the existing CA and gateway password,
issues a new server certificate, and updates `.env`. Recreate the gateway,
Gitea, Jenkins, Grafana, and Prometheus to load updated public URLs. Use a
stable DNS name when one is available.

## Migrate an existing lab

Back up `.env`, Compose/proxy configuration, Gitea `app.ini`, Jenkins job and
location configuration, and the database before cutover. Preserve existing
application volumes. Ensure Jenkins has no running or queued build.

1. Pull the exact GitHub commit on Kali; generate TLS and gateway credentials.
2. Change each Jenkins push webhook to
   `http://172.18.0.100:8080/jenkins/generic-webhook-trigger/invoke`, keeping
   its current token query and signing secret private.
3. Set Jenkins Location URL to `${PUBLIC_URL}/jenkins/`. Its Compose startup
   option is now `--prefix=/jenkins`; Prometheus scrapes `/jenkins/prometheus`.
4. Build the dashboard on Kali so its assets and API URLs use `/dashboard`.
5. Recreate the changed services and start the gateway. Gitea must release its
   old host binding on 3000 before the gateway can bind it. Compose automatically
   removes the old bindings when those service containers are recreated.
6. Change the server's Gitea Git remote to HTTPS on port 3000. Trust the lab CA
   for that origin. Internal Jenkins/worker Git operations still use
   `http://sg-gitea:3000`.

For this checkout's usual server remote:

```bash
git remote set-url origin https://localhost:3000/BeyondBug/VigilentOps
git config http.https://localhost:3000/.sslCAInfo "$PWD/secrets/gateway/ca.pem"
git ls-remote origin refs/heads/main
```

Gitea-generated clone and PR links use the configured public HTTPS URL.
Jenkins normalizes only explicitly configured Gitea origins to its internal
clone URL, then applies the existing owner/repository path allowlist. Gitea
webhooks, scanner uploads, AI workers, Grafana data sources, and Promtail
operate directly on the Docker network.

## Verify and recover

```bash
docker compose --profile ci --profile monitoring config --quiet
docker exec sg-gateway nginx -t
docker ps --format '{{.Names}} {{.Ports}}'
curl --cacert secrets/gateway/ca.pem -I https://localhost:3000/
curl --cacert secrets/gateway/ca.pem -I https://localhost:3000/grafana/login
curl --cacert secrets/gateway/ca.pem -I https://localhost:3000/jenkins/login
python3 scripts/audit_scan_coverage.py
```

Confirm unauthenticated dashboard/Jenkins/Prometheus requests get HTTP 401; login
allows the dashboard's assets, scan API and CVE feed. Check Grafana login,
panel queries and WebSockets, Jenkins login/crumb requests, and Git clone/push.
Trigger a Gitea push and confirm the resulting Jenkins scan reaches the exact
commit. Inspect Docker port bindings: only `sg-gateway` should publish 3000.
Check the old service ports are unreachable. Optional CI/monitoring routes
return an upstream error when that profile is deliberately stopped; they
never fall back to another service.

To roll back, stop the gateway, restore the backed-up Compose/environment and
Gitea/Jenkins configuration, restore each previous webhook URL, rebuild the
previous dashboard, and recreate the affected containers with their existing
volumes. Restore the prior Git remote and CA setting. Do not delete volumes
or restore an entire database over new scan records just to undo URL changes.

Nginx terminates TLS, forwards explicit host/protocol headers, supports
WebSockets, and omits query strings from access logs. Gitea stays at the root
as recommended by its [reverse proxy guide](https://docs.gitea.com/administration/reverse-proxies/).
Jenkins and Grafana use their supported prefix/root URL settings:
[Jenkins proxy documentation](https://www.jenkins.io/doc/book/system-administration/reverse-proxy-configuration-with-jenkins/),
[Grafana proxy documentation](https://grafana.com/tutorials/run-grafana-behind-a-proxy/).
