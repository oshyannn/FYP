"""User queries (Model layer). Roles are never taken from user input: sign-up always creates role 'user'."""
from __future__ import annotations

import psycopg

import config
from web import db
from web.security import make_username

_COLS = ("id, email::text AS email, username, full_name, password_hash, role::text AS role, "
         "is_email_verified, status::text AS status, locked_until")


def get_by_email(email: str):
    return db.one(f"SELECT {_COLS} FROM public.users WHERE email = %s", (email,))


def get_by_id(user_id):
    return db.one(f"SELECT {_COLS} FROM public.users WHERE id = %s", (user_id,))


def create_user(email: str, full_name: str, password_hash: str):
    """Creates a role 'user' account (role/status/verified use the column defaults). None if the email exists."""
    for _ in range(3):
        try:
            row = db.one(
                "INSERT INTO public.users (email, username, full_name, password_hash) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT (email) DO NOTHING RETURNING id",
                (email, make_username(email), full_name, password_hash))
            return row["id"] if row else None
        except psycopg.errors.UniqueViolation:       # random username suffix collided: try another
            continue
    return None


def mark_verified(user_id) -> None:
    db.run("UPDATE public.users SET is_email_verified = true, "
           "status = CASE WHEN status = 'pending' THEN 'active'::public.account_status ELSE status END "
           "WHERE id = %s", (user_id,))


def record_failed_login(user_id) -> None:
    db.run("""UPDATE public.users SET
                failed_login_count = CASE WHEN failed_login_count + 1 >= %(max)s THEN 0 ELSE failed_login_count + 1 END,
                locked_until = CASE WHEN failed_login_count + 1 >= %(max)s
                                    THEN now() + %(mins)s * interval '1 minute' ELSE locked_until END
              WHERE id = %(id)s""",
           {"max": config.MAX_FAILED_LOGINS, "mins": config.LOCK_MINUTES, "id": user_id})


def record_login_success(user_id) -> None:
    db.run("UPDATE public.users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() WHERE id = %s",
           (user_id,))


def set_password(user_id, password_hash: str) -> None:
    db.run("UPDATE public.users SET password_hash = %s, password_changed_at = now(), "
           "failed_login_count = 0, locked_until = NULL WHERE id = %s", (password_hash, user_id))


def update_hash(user_id, password_hash: str) -> None:
    db.run("UPDATE public.users SET password_hash = %s WHERE id = %s", (password_hash, user_id))


def create_employer_application(user_id, company_name: str, registration_no: str) -> None:
    """Employers are ordinary users until an administrator approves this application."""
    with db.transaction() as c:
        v = c.execute("INSERT INTO public.employer_verifications (user_id, company_name, company_registration_no) "
                      "VALUES (%s, %s, %s) RETURNING id", (user_id, company_name, registration_no)).fetchone()
        c.execute("INSERT INTO public.approval_requests (requester_id, verification_id, request_type) "
                  "VALUES (%s, %s, 'employer_verification')", (user_id, v["id"]))


def update_full_name(user_id, full_name: str) -> None:
    db.run("UPDATE public.users SET full_name = %s WHERE id = %s", (full_name, user_id))


def get_profile(user_id):
    return db.one("SELECT id, email::text AS email, full_name, role::text AS role, is_email_verified, "
                  "status::text AS status, created_at, last_login_at FROM public.users WHERE id = %s", (user_id,))
