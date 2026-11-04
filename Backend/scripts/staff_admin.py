"""Create the first admin, approve employers, and reset a password as a last resort. Run from Backend/:

    python -m scripts.staff_admin create-admin you@example.com "Your Name"
    python -m scripts.staff_admin approve-employer employer@example.com
    python -m scripts.staff_admin reset-password someone@example.com

Only this script (and later admin pages) can create privileged roles: the database trigger refuses
admin/employer inserts and promotions unless app.privileged_role_write is switched on inside the transaction.
"""
from __future__ import annotations

import argparse
import getpass
import sys

import config
from web import db
from web.security import clean_email, hash_password, make_username, password_errors


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


def reset_password(email_raw: str) -> None:
    """Last resort for a locked-out account, for example the only administrator. Normally people use "Forgot password"
    or an administrator's "Send Password Reset Email". The new password is typed here and never printed."""
    email, err = clean_email(email_raw)
    if err:
        sys.exit(err)
    with db.transaction() as c:
        row = c.execute("SELECT id, full_name, status::text AS status FROM public.users "
                        "WHERE email = %s AND status::text <> 'deleted'", (email,)).fetchone()
    if not row:
        sys.exit("No account with that address (deleted accounts cannot be reset).")
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    errs = password_errors(pw, email, row["full_name"] or "")
    if errs:
        sys.exit(" ".join(errs))
    with db.transaction() as c:
        c.execute("UPDATE public.users SET password_hash = %s, password_changed_at = now(), failed_login_count = 0, "
                  "locked_until = NULL WHERE id = %s", (hash_password(pw), row["id"]))
        c.execute("UPDATE public.sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL", (row["id"],))
        c.execute("INSERT INTO public.activity_logs (user_id, action, module, details) "
                  "VALUES (%s, 'password_reset_via_script', 'auth', '{}'::jsonb)", (row["id"],))
    print(f"Password for {email} changed. All its sessions were ended.")
    if row["status"] != "active":
        print(f"Note: the account status is '{row['status']}', so it still cannot sign in.")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("create-admin")
    a.add_argument("email")
    a.add_argument("name")
    e = sub.add_parser("approve-employer")
    e.add_argument("email")
    r = sub.add_parser("reset-password")
    r.add_argument("email")
    args = p.parse_args()
    if not config.DATABASE_URL:
        sys.exit("Set DATABASE_URL in Backend/.env first.")
    db.init_pool(config.DATABASE_URL)
    if args.cmd == "create-admin":
        create_admin(args.email, args.name)
    elif args.cmd == "approve-employer":
        approve_employer(args.email)
    else:
        reset_password(args.email)
