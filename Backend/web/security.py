"""Password hashing, token helpers and input validation."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from email_validator import EmailNotValidError, validate_email

import config

_hasher = PasswordHasher()                       # Argon2id
DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))   # verified when the account does not exist (equal timing)

# Same pattern as the CHECK constraint on public.users.email, so the database never rejects a "valid" address.
_DB_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_COMMON = {"password", "password1", "password123", "1234567890", "12345678910", "qwertyuiop", "iloveyou123",
           "admin12345", "letmein1234", "welcome1234", "safebrowse1"}


def hash_password(pw: str) -> str:
    return _hasher.hash(pw)


def verify_password(stored_hash: str, pw: str) -> bool:
    try:
        return _hasher.verify(stored_hash, pw)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Only this hash is stored in the database; a leaked table cannot be used to log in."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def password_errors(pw: str, email: str = "", full_name: str = "") -> list[str]:
    errs = []
    if len(pw) < 10:
        errs.append("Use at least 10 characters.")
    if len(pw) > 128:
        errs.append("Use at most 128 characters.")
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        errs.append("Include at least one letter and one number.")
    low = pw.lower()
    local = email.split("@")[0].lower()
    if len(local) >= 4 and local in low:
        errs.append("Do not include your email name in the password.")
    if low in _COMMON:
        errs.append("This password is too common.")
    return errs


def clean_email(raw: str | None) -> tuple[str | None, str | None]:
    """Returns (normalised_email, error_message). Deliverability is proven by the emailed link, not by DNS."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 254:
        return None, "Enter a valid email address."
    try:
        email = validate_email(raw, check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        return None, "Enter a valid email address."
    if not _DB_EMAIL.fullmatch(email):
        return None, "Enter a valid email address."
    if config.ALLOWED_EMAIL_DOMAINS and email.rsplit("@", 1)[1] not in config.ALLOWED_EMAIL_DOMAINS:
        return None, "Use an email from: " + ", ".join(sorted(config.ALLOWED_EMAIL_DOMAINS)) + "."
    return email, None


def make_username(email: str) -> str:
    local = re.sub(r"[^A-Za-z0-9_.-]", "", email.split("@")[0])[:30] or "user"
    return f"{local}_{secrets.token_hex(3)}"


# ---- one-time codes -------------------------------------------------------------------------------------
# Emailed codes have only 10^6 values, so a plain hash could be reversed instantly if the table leaked.
# They are stored as HMAC(SECRET_KEY, ...) instead, and each code allows only a few wrong attempts.
_PAIR_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"        # no 0/O/1/I/L


def make_code() -> str:
    return f"{secrets.randbelow(10 ** 6):06d}"


def make_pairing_code() -> str:
    return "".join(secrets.choice(_PAIR_ALPHABET) for _ in range(8))


def normalize_pairing_code(raw: str) -> str:
    code = re.sub(r"[\s-]", "", raw or "").upper()
    return code if re.fullmatch(f"[{_PAIR_ALPHABET}]{{8}}", code) else ""


def is_code(raw: str) -> bool:
    return bool(re.fullmatch(r"\d{6}", raw or ""))


def code_hash(scope: str, value: str) -> str:
    return hmac.new(config.SECRET_KEY.encode("utf-8"), f"{scope}|{value}".encode("utf-8"), hashlib.sha256).hexdigest()
