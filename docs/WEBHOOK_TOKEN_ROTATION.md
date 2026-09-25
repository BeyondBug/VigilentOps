# Jenkins webhook token rotation

The current shared Jenkinsfile has a literal Generic Webhook Trigger token.
All existing Gitea hooks use it, so replacing it requires a coordinated
Jenkins and Gitea change on the server. Treat this as a production exposure
gate; the lab keeps working until that maintenance window.

1. In Jenkins, create a **Secret text** credential for a new random webhook
   token. Give it a distinct ID such as `gitea-webhook-token`. Restrict its
   scope to the pipeline that needs it. Do not reuse `gitea-cred`, the Gitea
   API token, or `SG_API_KEY`.
2. Replace the `GenericTrigger` `token:` argument in the shared Jenkinsfile
   with `tokenCredentialId: 'gitea-webhook-token'`. Push the change to GitHub,
   pull it on the server, and push the exact commit to Gitea `main`.
3. Run the Jenkins pipeline once so the changed trigger is applied to the
   job configuration. Confirm the job shows the credential-backed trigger.
4. Update every intended Gitea repository's push hook to send the new token
   to Jenkins. Never print the token in a console log or commit it to a file.
   Check each hook's recent-delivery status and trigger an accepted-branch
   push. Record the delivered commit and matching Jenkins build/scan ID.
5. Remove the old token from active hooks and rotate any related credential
   that has been exposed in logs or repository history. Check that a request
   with the old token no longer starts a build.

Before production exposure, also restrict which clone URLs the pipeline will
accept. Decide the canonical Gitea URL and host after inspecting the server's
actual webhook payloads. Reject other schemes/hosts and credentials embedded
in URLs before Jenkins clones a target. Then verify all intended repositories
still scan. Do not guess the host from the development laptop's network.

The Generic Webhook Trigger plugin documents `tokenCredentialId` for a
Jenkins Secret text credential and notes that a pipeline must run once to
apply a new trigger configuration: [plugin documentation](https://github.com/jenkinsci/generic-webhook-trigger-plugin).
