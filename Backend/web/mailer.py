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


def send_staff_invite(to: str, name: str, role: str, code: str, hours: int) -> bool:
    """The email for a staff invitation. Nothing is created until the person uses the code."""
    what = "an administrator" if role == "admin" else "an employer"
    pin_line = ("This is an administrator account, so you also need the PIN the person who invited you gave you "
                "by phone or chat. The PIN is not in this email.\n\n") if role == "admin" else ""
    return send(to, "You are invited to SafeBrowse",
                f"Hello {name},\n\nYou were invited to join SafeBrowse as {what}.\n\n"
                "To activate your account, open the SafeBrowse desktop app, choose Staff login, then "
                "\"Activate an invited account\". Enter this email address, this 6-digit code and a new password of your choice:\n"
                f"{code}\n\n{pin_line}The code expires in {hours} hours and works once. Never share it with anyone. "
                "If you did not expect this invitation, ignore this email: nothing is created until you use the code.\n")

def send_employer_credentials(to: str, name: str | None, password: str, hours: int) -> bool:
    """New employer account: the login email and a random temporary password."""
    return send(to, "Your SafeBrowse employer account",
                f"Hello {name or 'there'},\n\nAn administrator created a SafeBrowse employer account for you.\n\n"
                f"Email: {to}\nTemporary password: {password}\n\n"
                "To start, open the SafeBrowse desktop app, choose Staff login and sign in with the details above. "
                "You will be asked to choose your own password straight away; nothing else can be used before that.\n\n"
                f"The temporary password works for {hours} hours. Delete this email after you have changed it. "
                "If you did not expect it, ignore this email and tell your administrator.\n")


def send_reset_credentials(to: str, name: str | None, password: str, hours: int) -> bool:
    """An administrator reset the password: a new random temporary password."""
    return send(to, "Your SafeBrowse password was reset",
                f"Hello {name or 'there'},\n\nAn administrator reset your SafeBrowse password.\n\n"
                f"Email: {to}\nTemporary password: {password}\n\n"
                "Open the SafeBrowse desktop app and sign in with the details above (employers and administrators use "
                "Staff login). You will be asked to choose your own password straight away; nothing else can be used "
                "before that.\n\n"
                f"The temporary password works for {hours} hours, and your old password no longer works. Delete this "
                "email after you have changed it. If you did not expect this, tell your administrator.\n")