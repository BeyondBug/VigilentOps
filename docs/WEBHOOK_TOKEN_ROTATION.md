# Jenkins webhook token migration and rotation

The shared Jenkinsfile now uses Secret text credential ID
`gitea-webhook-token`. The previously deployed job/hooks may still hold the
historical literal token. Migration must be coordinated on Kali; the code
change alone does not rotate deployed credentials.

1. Back up the database, private settings, Jenkins volume and Gitea hooks.
   Finish running/queued work. Preserve rollback images and snapshots.
2. Run `python3 scripts/prepare_jenkins_security.py`. It prepares a private
   administrator, metrics password and random webhook token in ignored
   `secrets/jenkins/`. Existing generated credentials are retained on rerun.
3. Build/recreate Jenkins, gateway and Prometheus; verify native accounts,
   CSRF and metrics permissions. Pull the exact GitHub code and push Gitea
   through the existing HTTPS workflow. See [Next server session](NEXT_SERVER_SESSION.md).
4. Run the updated shared pipeline once, using the previous job trigger or
   an administrator-started build with the required push variables. Confirm
   the job now references `gitea-webhook-token` before changing any hook.
5. Preview `python3 scripts/manage_gitea_hooks.py`, then run it with `--apply`.
   It changes only the matching active Jenkins push hook per repository,
   retains signing settings/events, and replaces the private query token.
   Missing/ambiguous hooks or unexpected hosts stop the operation. No token is
   printed; API redirects are refused. Private hook backups contain secrets.
6. Run the script with `--test`. Record delivery status, build ID, target
   commit, scan ID and completed result for every intended repository. Queued
   deliveries alone do not establish coverage.
7. Check the old token no longer starts builds on the internal endpoint and
   the public endpoint stays blocked. Do not print tokens in commands/logs.

For later rotation, schedule maintenance, preserve a private backup, replace
only `webhook_token` in the ignored bootstrap JSON with a freshly generated
random value, recreate Jenkins and repeat trigger/hook verification. Preparation
retains existing tokens deliberately; it is not a periodic rotation command.

The URL allowlist and exact target-commit checks run before scan registration.
Test rejected origins and accepted repositories after rotation. Tokens authorize
build execution; protect the Docker network as well as the gateway. The plugin
notes that token-triggered builds run as SYSTEM:
[Generic Webhook Trigger documentation](https://github.com/jenkinsci/generic-webhook-trigger-plugin).
