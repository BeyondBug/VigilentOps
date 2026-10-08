// Runs last, including after the historical disable-csrf.groovy on this lab.
// Private credentials are prepared on Kali; they never enter Git or logs.
import groovy.json.JsonSlurper
import jenkins.model.Jenkins
import hudson.security.HudsonPrivateSecurityRealm
import hudson.security.GlobalMatrixAuthorizationStrategy
import hudson.security.csrf.DefaultCrumbIssuer
import org.jenkinsci.plugins.matrixauth.PermissionEntry
import com.cloudbees.plugins.credentials.CredentialsScope
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
import com.cloudbees.plugins.credentials.domains.Domain
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl
import hudson.util.Secret
import hudson.security.Permission
import org.jenkinsci.plugins.prometheus.config.PrometheusConfiguration

def instance = Jenkins.get()
def realm = new HudsonPrivateSecurityRealm(false)
def matrix = new GlobalMatrixAuthorizationStrategy()
def source = new File('/run/secureguard-jenkins/bootstrap.json')
instance.setSecurityRealm(realm)
instance.setAuthorizationStrategy(matrix)
instance.setCrumbIssuer(new DefaultCrumbIssuer(true))
instance.save()
// Missing bootstrap must never restore anonymous administration.
if (!source.isFile()) {
    throw new IllegalStateException('Prepare private Jenkins bootstrap on the server first')
}
def settings = new JsonSlurper().parse(source)
assert settings.admin_user ==~ /[A-Za-z0-9_.-]+/
assert settings.admin_password && settings.metrics_password && settings.webhook_token
assert settings.admin_user != settings.metrics_user
realm.createAccount(settings.admin_user as String, settings.admin_password as String)
realm.createAccount(settings.metrics_user as String, settings.metrics_password as String)
matrix.add(Jenkins.ADMINISTER, PermissionEntry.user(settings.admin_user as String))
matrix.add(Jenkins.READ, PermissionEntry.user(settings.metrics_user as String))
def metricsView = Permission.fromId('jenkins.metrics.api.Metrics.View')
if (metricsView == null) {
    throw new IllegalStateException('Metrics plugin permission is unavailable')
}
matrix.add(metricsView, PermissionEntry.user(settings.metrics_user as String))
instance.setSecurityRealm(realm)
instance.setAuthorizationStrategy(matrix)
instance.setCrumbIssuer(new DefaultCrumbIssuer(true))
def provider = SystemCredentialsProvider.getInstance()
def store = provider.getStore()
def credential = new StringCredentialsImpl(CredentialsScope.GLOBAL,
    'gitea-webhook-token', 'Private Gitea push trigger', Secret.fromString(settings.webhook_token as String))
def existing = provider.getCredentials().find { it.id == 'gitea-webhook-token' }
if (existing) {
    assert store.updateCredentials(Domain.global(), existing, credential)
} else {
    assert store.addCredentials(Domain.global(), credential)
}
def prometheus = PrometheusConfiguration.get()
prometheus.setUseAuthenticatedEndpoint(true)
prometheus.save()
provider.save()
instance.save()
println('SecureGuard Jenkins authentication, account permissions and CSRF enabled')
