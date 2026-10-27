"""Create the first admin and approve employers (until the admin dashboard exists). Run from backend/:

    python -m scripts.staff_admin create-admin you@example.com "Your Name"
    python -m scripts.staff_admin approve-employer employer@example.com

Only this script (and later admin pages) can create privileged roles: the database trigger refuses
admin/employer inserts and promotions unless app.privileged_role_write is switched on inside the transaction.
"""
from __future__ import annotations

import argparse
import getpass
import sys

import config
import db
from security import clean_email, hash_password, make_username, password_errors


def _allow_privileged(conn) -> None:
    conn.execute("SELECT set_config('app.privileged_role_write', 'on', true)")   # true = this transaction only


def create_admin(email_raw: str, name: str) -> None:
    email, err = clean_email(email_raw)
    if err:
        sys.exit(err)
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    errs = password_errors(pw, email, name)
    if errs:
        sys.exit(" ".join(errs))
    with db.transaction() as c:
        _allow_privileged(c)
        c.execute("INSERT INTO public.users (email, username, full_name, password_hash, role, is_email_verified, status) "
                  "VALUES (%s, %s, %s, %s, 'admin', true, 'active')",
                  (email, make_username(email), name, hash_password(pw)))
        c.execute("INSERT INTO public.activity_logs (action, module, details) "
                  "VALUES ('admin_created_via_script', 'auth', '{}'::jsonb)")
    print(f"Admin {email} created. Log in at /staff/login")


def approve_employer(email_raw: str) -> None:
    email, err = clean_email(email_raw)
    if err:
        sys.exit(err)
    with db.transaction() as c:
        _allow_privileged(c)
        row = c.execute(
            "SELECT u.id, v.id AS vid FROM public.users u JOIN public.employer_verifications v ON v.user_id = u.id "
            "WHERE u.email = %s AND u.is_email_verified AND u.role = 'user' AND v.verification_status = 'pending' "
            "ORDER BY v.submitted_at DESC LIMIT 1", (email,)).fetchone()
        if not row:
            sys.exit("No pending application from an email-verified account with that address.")
        c.execute("UPDATE public.users SET role = 'employer' WHERE id = %s", (row["id"],))
        c.execute("UPDATE public.employer_verifications SET verification_status = 'approved' WHERE id = %s", (row["vid"],))
        c.execute("UPDATE public.approval_requests SET status = 'approved' WHERE verification_id = %s", (row["vid"],))
        c.execute("INSERT INTO public.activity_logs (user_id, action, module, details) "
                  "VALUES (%s, 'employer_approved_via_script', 'auth', '{}'::jsonb)", (row["id"],))
        c.execute("UPDATE public.sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL", (row["id"],))
    print(f"{email} is now an employer and can log in at /staff/login")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("create-admin")
    a.add_argument("email")
    a.add_argument("name")
    e = sub.add_parser("approve-employer")
    e.add_argument("email")
    args = p.parse_args()
    if not config.DATABASE_URL:
        sys.exit("Set DATABASE_URL in backend/.env first.")
    db.init_pool(config.DATABASE_URL)
    create_admin(args.email, args.name) if args.cmd == "create-admin" else approve_employer(args.email)
