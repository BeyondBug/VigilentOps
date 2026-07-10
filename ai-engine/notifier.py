import os, httpx, smtplib
from email.mime.text import MIMEText

class Notifier:
    def __init__(self):
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat = os.getenv("TELEGRAM_CHAT_ID", "")
        self.smtp_host = os.getenv("SMTP_HOST", "")
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_pass = os.getenv("SMTP_PASS", "")
        self.admin_email = os.getenv("ADMIN_EMAIL", "")

    def send_alert(self, repo: str, commit: str, critical_findings: list):
        msg = f"""🚨 *SecureGuard Alert*

*Repo:* `{repo}`
*Commit:* `{commit[:8]}`
*Critical findings:* {len(critical_findings)}

Top finding:
- *{critical_findings[0].get('rule_id', 'unknown')}*
- CVSS: {critical_findings[0].get('cvss_score', 'N/A')}
- {critical_findings[0].get('message', '')[:100]}

AI fix PR opened in Gitea ✅"""

        if self.telegram_token and self.telegram_chat:
            self._send_telegram(msg)
        if self.smtp_host and self.admin_email:
            self._send_email(repo, msg)

    def _send_telegram(self, message: str):
        try:
            with httpx.Client() as client:
                client.post(
                    f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                    json={"chat_id": self.telegram_chat, "text": message, "parse_mode": "Markdown"}
                )
        except Exception as e:
            print(f"Telegram error: {e}")

    def _send_email(self, subject: str, body: str):
        try:
            msg = MIMEText(body)
            msg["Subject"] = f"[SecureGuard] Critical vulnerability in {subject}"
            msg["From"] = self.smtp_user
            msg["To"] = self.admin_email
            with smtplib.SMTP(self.smtp_host, int(os.getenv("SMTP_PORT", 587))) as s:
                s.starttls()
                s.login(self.smtp_user, self.smtp_pass)
                s.send_message(msg)
        except Exception as e:
            print(f"Email error: {e}")
