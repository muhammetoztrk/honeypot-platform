import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from . import models


def send_alert_email(alert: models.Alert, db):
    """Send email notification for high-risk alerts"""
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    alert_email = os.getenv("ALERT_EMAIL", "")

    if not smtp_host or not alert_email:
        return  # Email not configured, silently skip

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = alert_email
        msg["Subject"] = f"[Honeypot Alert] {alert.severity.upper()}: {alert.title}"

        body = f"""
        Honeypot Deception Platform Alert
        
        Severity: {alert.severity.upper()}
        Title: {alert.title}
        Message: {alert.message}
        Time: {alert.created_at}
        
        Please review the alert in the dashboard.
        """
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.send_message(msg)
    except Exception:
        pass  # Silently fail if email sending fails

