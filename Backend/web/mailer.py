"""Gmail SMTP sender (STARTTLS + app password). In development without credentials it prints the mail instead."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

import config

log = logging.getLogger(__name__)


def send(to: str, subject: str, body: str) -> bool:
    if not (config.GMAIL_USER and config.GMAIL_APP_PASSWORD):
        if config.IS_PROD:
            log.error("Gmail SMTP is not configured; mail not sent")
            return False
        print(f"\n[DEV MAIL] to: {to}\nsubject: {subject}\n{body}\n")
        return True
    msg = EmailMessage()
    msg["From"] = f"{config.MAIL_FROM_NAME} <{config.GMAIL_USER}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as s:
            s.starttls(context=ssl.create_default_context())
            s.login(config.GMAIL_USER, config.GMAIL_APP_PASSWORD)
            s.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError):
        log.exception("Sending mail failed")
        return False


def send_verification_code(to: str, code: str, link: str | None = None) -> bool:
    link_part = (f"Option 1 - click this link to confirm (the SafeBrowse app then signs you in automatically):\n{link}\n\n"
                 if link else "")
    return send(to, "Confirm your SafeBrowse email",
                f"Hello,\n\n{link_part}Option 2 - enter this 6-digit code in the app (also works from another device):\n"
                f"{code}\n\nThe code expires in {config.VERIFY_CODE_MINUTES} minutes. Never share it with anyone. "
                "If you did not sign up, ignore this email.\n")


def send_reset_code(to: str, code: str) -> bool:
    return send(to, "Your SafeBrowse password reset code",
                f"Hello,\n\nYour SafeBrowse password reset code is: {code}\n\n"
                f"It expires in {config.RESET_CODE_MINUTES} minutes and works once. Never share it with anyone. "
                "If you did not ask for this, ignore this email; your password stays the same.\n")
