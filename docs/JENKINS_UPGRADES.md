# Jenkins upgrades

The controller image uses Jenkins **2.580.1 LTS / Java 25**, pinned by digest.
Installed plugin versions are managed in [plugins.txt](../jenkins/plugins.txt).
The initial list preserves the 97 existing plugins, using compatible releases
from the official stable update center on 1 October 2026. The plugin manager
resolves additional dependencies during the server build.

The [official download page](https://www.jenkins.io/download/) lists this LTS.
The [September security advisory](https://www.jenkins.io/security/advisory/2026-09-02/)
explains the affected older core and plugin versions. Read every intervening
[LTS upgrade guide](https://www.jenkins.io/doc/upgrade-guide/) before upgrading.
Java versions used inside scanner containers are independent of the controller
JVM; see the [Java support policy](https://www.jenkins.io/doc/book/platform-information/support-policy-java/).

The controller omits `openssh-client`: the lab has only the built-in node,
and accepted repository clones use HTTP/HTTPS. Its Git functionality is
verified through a real pipeline push. Host SSH is managed separately. If
SSH Git remotes or SSH-launched agents are introduced later, provide a
patched client explicitly and test that new transport; this image does not
support it.

## Upgrade sequence on Kali

1. Check controller and plugin advisories. Update the explicit image version,
   verified registry digest and compatible plugin pins together. Do not treat
   an old cached `lts` tag as an update.
2. Build `docker compose build --pull jenkins` on Kali. Retain the exact old
   image ID and create a private consistent Jenkins volume/configuration
   backup while its builds and queue are idle.
3. Rehearse the new image against a restored snapshot:

   ```bash
   python3 scripts/verify_restored_services.py /absolute/path/to/backup \
     --jenkins-image sha256:EXACT_LOCALLY_BUILT_IMAGE_ID \
     --output reports/jenkins-upgrade-trial.json
   ```

   This uses disposable volumes and an internal network, runs the snapshot's
   native security startup script, verifies enabled plugins load, and keeps
   Jenkins quiet with zero executors. It does not run the real pipeline.
4. Recreate only Jenkins with the built image in the maintenance window.
   Compose enables the official image's `PLUGINS_FORCE_UPGRADE` and
   `TRY_UPGRADE_IF_NO_MARKER` behavior so managed newer reference plugins
   reach an existing persistent home. Merely rebuilding the image can leave
   old manually installed plugins in the volume. See the
   [official Docker upgrade behavior](https://github.com/jenkinsci/docker#upgrading-plugins).
5. Verify administrator login, anonymous denial, metrics account permissions,
   CSRF, plugin activation, security warnings, the shared pipeline parser,
   authenticated metrics and a real Gitea push through the report contract.
   Record versions, backup path, image ID, build and scan in the dated record.

Use the container/image upgrade procedure for this setup; the UI's automatic
WAR upgrade is not the version definition stored in Git. Keep every backup
and raw upgrade log private. A Jenkins restart briefly interrupts its UI and
metrics endpoint.

## Recovery

Do not run an older core against plugin files/configuration upgraded by a
newer release. Restore the pre-upgrade archive into a **new** volume and run
the recorded old image against that volume. Keep the upgraded volume intact
until recovery succeeds. Restore private startup/bootstrap configuration from
the same snapshot, then repeat authentication and pipeline checks. The
isolated rehearsal and volume checks do not replace this coordinated rollback.

Running builds on the controller with its Docker socket remains a lab
architecture constraint. Production needs isolated build agents and a review
of their credentials, network access and privileges.
