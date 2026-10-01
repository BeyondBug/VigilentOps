import os, httpx, smtplib
import logging
import ssl

log = logging.getLogger("notifications")
# HTTPX INFO request logs include credential-bearing webhook/bot URLs.
logging.getLogger('httpx').setLevel(logging.WARNING)
from email.mime.text import MIMEText

class Notifier:
    def __init__(self):
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat = os.getenv("TELEGRAM_CHAT_ID", "")
        
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL", "")
        
        self.twilio_sid = os.getenv("TWILIO_ACCOUNT_SID", "")
        self.twilio_auth = os.getenv("TWILIO_AUTH_TOKEN", "")
        self.twilio_from = os.getenv("TWILIO_WHATSAPP_FROM", "")
        self.twilio_to = os.getenv("TWILIO_WHATSAPP_TO", "")

        self.jira_url = os.getenv("JIRA_URL", "")
        self.jira_user = os.getenv("JIRA_USER", "")
        self.jira_token = os.getenv("JIRA_API_TOKEN", "")
        self.jira_key = os.getenv("JIRA_PROJECT_KEY", "SG")
        
        self.smtp_host = os.getenv("SMTP_HOST", "")
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_pass = os.getenv("SMTP_PASS", "")
        self.admin_email = os.getenv("ADMIN_EMAIL", "")

    def send_alert(self, repo: str, commit: str, critical_findings: list):
        if not critical_findings:
            return {}

        top_finding = critical_findings[0]
        # External notifications carry identifiers only, never source snippets/descriptions.
        msg = (f"SecureGuard security alert\nRepo: {repo}\nCommit: {commit[:8]}\n"
               f"High/critical finding records: {len(critical_findings)}\n"
               f"Scanner: {top_finding.get('scanner', 'unknown')}\n"
               f"Rule: {top_finding.get('rule_id', 'unknown')}\n"
               f"Severity: {top_finding.get('severity', 'UNKNOWN')}\n"
               "Review details in the authenticated dashboard. AI proposals require review and validation.")
        results = {}

        if self.telegram_token and self.telegram_chat:
            results["telegram"] = self._send_telegram(msg)
        if self.slack_webhook:
            results["slack"] = self._send_slack(msg)
        if self.twilio_sid and self.twilio_auth and self.twilio_to:
            results["whatsapp"] = self._send_whatsapp(msg)
        if self.jira_url and self.jira_token:
            results["jira"] = self._create_jira_ticket(repo, top_finding)
        if self.smtp_host and self.admin_email:
            results["email"] = self._send_email(repo, msg)

        return results

    def _send_telegram(self, message: str):
        try:
            with httpx.Client(timeout=15) as client:
                response = client.post(
                    f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                    json={"chat_id": self.telegram_chat, "text": message}
                )
            response.raise_for_status()
            return True
        except Exception as e:
            log.error("Telegram delivery failed: %s", type(e).__name__)
            return False

    def _send_slack(self, message: str):
        try:
            with httpx.Client(timeout=15) as client:
                response = client.post(self.slack_webhook, json={"text": message})
            response.raise_for_status()
            return True
        except Exception as e:
            log.error("Slack delivery failed: %s", type(e).__name__)
            return False

    def _send_whatsapp(self, message: str):
        try:
            auth = (self.twilio_sid, self.twilio_auth)
            data = {
                "From": self.twilio_from,
                "To": self.twilio_to,
                "Body": message
            }
            with httpx.Client(timeout=15) as client:
                response = client.post(
                    f"https://api.twilio.com/2010-04-01/Accounts/{self.twilio_sid}/Messages.json",
                    auth=auth, data=data
                )
            response.raise_for_status()
            return True
        except Exception as e:
            log.error("WhatsApp delivery failed: %s", type(e).__name__)
            return False

    def _create_jira_ticket(self, repo: str, finding: dict):
        try:
            auth = (self.jira_user, self.jira_token)
            payload = {
                "fields": {
                    "project": {"key": self.jira_key},
                    "summary": f"Security Alert: {finding.get('rule_id', 'Vuln')} in {repo}",
                    "description": (f"Scanner: {finding.get('scanner', 'unknown')}\n"
                                    f"Rule: {finding.get('rule_id', 'unknown')}\n"
                                    f"Severity: {finding.get('severity', 'UNKNOWN')}\n"
                                    "Review the restricted dashboard for details; no source or credentials copied."),
                    "issuetype": {"name": "Task"}
                }
            }
            with httpx.Client(timeout=15) as client:
                response = client.post(f"{self.jira_url}/rest/api/2/issue", auth=auth, json=payload)
            response.raise_for_status()
            return True
        except Exception as e:
            log.error("Jira delivery failed: %s", type(e).__name__)
            return False

    def _send_email(self, subject: str, body: str):
        try:
            msg = MIMEText(body)
            msg["Subject"] = f"[SecureGuard] Critical vulnerability in {subject}"
            msg["From"] = self.smtp_user
            msg["To"] = self.admin_email
            with smtplib.SMTP(self.smtp_host, int(os.getenv("SMTP_PORT", 587)), timeout=15) as s:
                s.starttls(context=ssl.create_default_context())
                if self.smtp_user:
                    s.login(self.smtp_user, self.smtp_pass)
                if s.send_message(msg):
                    log.error("Email delivery failed: recipient refused")
                    return False
            return True
        except Exception as e:
            log.error("Email delivery failed: %s", type(e).__name__)
            return False
