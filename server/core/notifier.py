import asyncio
import smtplib
from email.message import EmailMessage
import os
from core.secrets_config import secrets

def _send_email_sync(msg, smtp_server, smtp_port, smtp_user, smtp_password):
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.set_debuglevel(0)
        server.ehlo()
        server.starttls()
        server.ehlo()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)

async def send_fraud_alert(transaction: dict, score: int):
    """
    Asynchronously sends an urgent email alert to the auditor when critical fraud is detected.
    """
    auditor_email = secrets.get("AUDITOR_EMAIL", "auditor@vaultmind.local")
    smtp_server = secrets.get("SMTP_SERVER", "localhost")
    smtp_port = secrets.get_int("SMTP_PORT", 1025)
    
    msg = EmailMessage()
    msg.set_content(f"""
    URGENT: CRITICAL FRAUD DETECTED
    
    A transaction has breached the strict >= 70 CBSI threshold.
    
    Transaction ID: {transaction.get('transaction_id')}
    Employee ID: {transaction.get('emp_id')}
    CBSI Score: {score}/100
    Amount: {transaction.get('amount')}
    
    Please review the evidence package immediately.
    """)
    
    msg['Subject'] = f"CRITICAL FRAUD ALERT - Score {score} - {transaction.get('emp_id')}"
    msg['From'] = "alerts@vaultmind.local"
    msg['To'] = auditor_email
    
    try:
        smtp_user = secrets.get("SMTP_USER")
        smtp_password = secrets.get("SMTP_PASSWORD")
        # Run blocking SMTP calls in thread pool to prevent event loop blocking
        await asyncio.to_thread(_send_email_sync, msg, smtp_server, smtp_port, smtp_user, smtp_password)
        print(f"[NOTIFIER] Fraud alert email sent to {auditor_email} for TXN {transaction.get('transaction_id')}")
    except Exception as e:
        print(f"[NOTIFIER] Failed to send email alert: {e}")

# ==========================================
# FUTURE CAPABILITY: TWILIO SMS INTEGRATION
# ==========================================
async def send_sms_alert(transaction: dict, score: int):
    """
    Sends an SMS alert via Twilio for critical breaches.
    """
    try:
        from twilio.rest import Client
    except ImportError:
        print("[NOTIFIER] Twilio module not installed. Skipping SMS.")
        return
    account_sid = secrets.get("TWILIO_ACCOUNT_SID")
    auth_token = secrets.get("TWILIO_AUTH_TOKEN")
    
    if not account_sid or not auth_token:
        print("[NOTIFIER] Missing Twilio credentials. Skipping SMS.")
        return

    try:
        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body=f"VAULTMIND ALERT: Critical Fraud (Score {score}) detected for {transaction.get('emp_id')}. Review dashboard.",
            from_=secrets.get("TWILIO_FROM_NUMBER"),
            to=secrets.get("AUDITOR_PHONE")
        )
        print(f"[NOTIFIER] SMS sent: {message.sid}")
    except Exception as e:
        print(f"[NOTIFIER] Failed to send SMS alert: {e}")

