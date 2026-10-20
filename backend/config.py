"""Settings come from environment variables (backend/.env). Nothing secret is hard-coded."""
from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()


def _int(name: str, default: int) -> int:
    return int(os.getenv(name, default))


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
IS_PROD = APP_ENV == "production"

SECRET_KEY = os.getenv("SECRET_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000").rstrip("/")   # used in the links inside emails
HTTPS = _bool("HTTPS", IS_PROD)                       # true when served over https (adds the HSTS header)

GMAIL_USER = os.getenv("GMAIL_USER", "")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "")
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "SafeBrowse")
ALLOWED_EMAIL_DOMAINS = {d.strip().lower() for d in os.getenv("ALLOWED_EMAIL_DOMAINS", "").split(",") if d.strip()}
CORS_ORIGINS = {o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()}
REQUIRE_AUTH_FOR_ANALYZE = _bool("REQUIRE_AUTH_FOR_ANALYZE", False)

# Desktop user: absolute lifetime and idle limit (minutes). "Remember me" keeps them logged in for days.
USER_SESSION_HOURS = _int("USER_SESSION_HOURS", 12)
USER_IDLE_MINUTES = _int("USER_IDLE_MINUTES", 60)
REMEMBER_DAYS = _int("REMEMBER_DAYS", 14)
REMEMBER_IDLE_DAYS = _int("REMEMBER_IDLE_DAYS", 14)
# Employer / admin: short and strict, never persistent.
STAFF_SESSION_HOURS = _int("STAFF_SESSION_HOURS", 4)
STAFF_IDLE_MINUTES = _int("STAFF_IDLE_MINUTES", 20)
# Paired browser extension.
EXT_SESSION_DAYS = _int("EXT_SESSION_DAYS", 30)
EXT_IDLE_DAYS = _int("EXT_IDLE_DAYS", 14)

MAX_FAILED_LOGINS = _int("MAX_FAILED_LOGINS", 5)
LOCK_MINUTES = _int("LOCK_MINUTES", 15)
VERIFY_CODE_MINUTES = _int("VERIFY_CODE_MINUTES", 15)
VERIFY_LINK_HOURS = _int("VERIFY_LINK_HOURS", 24)
HANDOFF_MINUTES = _int("HANDOFF_MINUTES", 30)
RESET_CODE_MINUTES = _int("RESET_CODE_MINUTES", 15)
CODE_MAX_ATTEMPTS = _int("CODE_MAX_ATTEMPTS", 5)
CODE_RESEND_SECONDS = _int("CODE_RESEND_SECONDS", 60)
PAIRING_CODE_MINUTES = _int("PAIRING_CODE_MINUTES", 5)


def auth_ready() -> bool:
    """The API is only enabled when the two essentials are present."""
    return bool(SECRET_KEY and DATABASE_URL)


def validate() -> list[str]:
    problems = []
    if len(SECRET_KEY) < 32:
        problems.append('SECRET_KEY must be at least 32 characters: python -c "import secrets; print(secrets.token_hex(32))"')
    if not DATABASE_URL.startswith(("postgresql://", "postgres://")):
        problems.append("DATABASE_URL must be a Postgres connection string (Supabase > Connect > Session pooler).")
    if IS_PROD:
        if not BASE_URL.startswith("https://"):
            problems.append("BASE_URL must be https:// in production.")
        if not HTTPS:
            problems.append("HTTPS must be true in production (serve the API over https).")
        if not (GMAIL_USER and GMAIL_APP_PASSWORD):
            problems.append("GMAIL_USER and GMAIL_APP_PASSWORD are required in production.")
    return problems
