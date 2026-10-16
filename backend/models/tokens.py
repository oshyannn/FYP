"""One-time codes: 6-digit emailed codes (verification, password reset) and extension pairing codes.
Stored as HMACs, single use, short lived; emailed codes also allow only a few wrong attempts."""
from __future__ import annotations

import hmac

import config
import db
from security import code_hash, is_code, make_code, make_pairing_code


def _otp_hash(user_id, purpose: str, code: str) -> str:
    return code_hash(f"{purpose}|{user_id}", code)


def issue_code(user_id, purpose: str, ttl_minutes: int) -> str:
    """Creates a fresh 6-digit code (older open codes for the same purpose stop working) and returns it."""
    code = make_code()
    with db.transaction() as c:
        c.execute("UPDATE public.auth_tokens SET consumed_at = now() "
                  "WHERE user_id = %s AND purpose = %s::public.token_purpose AND consumed_at IS NULL",
                  (user_id, purpose))
        c.execute("INSERT INTO public.auth_tokens (user_id, token_hash, purpose, expires_at) "
                  "VALUES (%s, %s, %s::public.token_purpose, now() + %s * interval '1 minute')",
                  (user_id, _otp_hash(user_id, purpose, code), purpose, ttl_minutes))
    return code


def recently_issued(user_id, purpose: str, seconds: int) -> bool:
    row = db.one("SELECT 1 AS x FROM public.auth_tokens WHERE user_id = %s AND purpose = %s::public.token_purpose "
                 "AND created_at > now() - %s * interval '1 second' LIMIT 1", (user_id, purpose, seconds))
    return row is not None


def verify_code(user_id, purpose: str, code: str) -> bool:
    """True once, for the right unexpired code. Wrong guesses are counted; too many kills the code."""
    if not is_code(code):
        return False
    with db.transaction() as c:
        row = c.execute("SELECT id, token_hash FROM public.auth_tokens "
                        "WHERE user_id = %s AND purpose = %s::public.token_purpose "
                        "AND consumed_at IS NULL AND expires_at > now() ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
                        (user_id, purpose)).fetchone()
        if not row:
            return False
        if hmac.compare_digest(row["token_hash"], _otp_hash(user_id, purpose, code)):
            c.execute("UPDATE public.auth_tokens SET consumed_at = now() WHERE id = %s", (row["id"],))
            return True
        c.execute("UPDATE public.auth_tokens SET attempts = attempts + 1, "
                  "consumed_at = CASE WHEN attempts + 1 >= %s THEN now() ELSE consumed_at END WHERE id = %s",
                  (config.CODE_MAX_ATTEMPTS, row["id"]))
        return False


def issue_pairing_code(user_id, ttl_minutes: int) -> str:
    code = make_pairing_code()
    with db.transaction() as c:
        c.execute("UPDATE public.auth_tokens SET consumed_at = now() "
                  "WHERE user_id = %s AND purpose = 'extension_pairing'::public.token_purpose AND consumed_at IS NULL",
                  (user_id,))
        c.execute("INSERT INTO public.auth_tokens (user_id, token_hash, purpose, expires_at) "
                  "VALUES (%s, %s, 'extension_pairing'::public.token_purpose, now() + %s * interval '1 minute')",
                  (user_id, code_hash("pairing", code), ttl_minutes))
    return code


def consume_pairing_code(code: str):
    """Atomically uses the code up and returns its user_id (None if invalid, expired or already used)."""
    row = db.one("UPDATE public.auth_tokens SET consumed_at = now() "
                 "WHERE token_hash = %s AND purpose = 'extension_pairing'::public.token_purpose "
                 "AND consumed_at IS NULL AND expires_at > now() RETURNING user_id", (code_hash("pairing", code),))
    return row["user_id"] if row else None
