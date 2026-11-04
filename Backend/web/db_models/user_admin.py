"""Accounts as an employer or an administrator sees them (Model layer).

Who sees and who changes whom. This is enforced here in SQL; the controller checks it again:
  administrator : sees users, employers and administrators. Changes users and employers.
                  Administrator accounts are read-only for now (changing one will need another administrator's approval).
  employer      : sees and changes users only. Never sees employers or administrators. Cannot delete.
Nobody can change their own account here. A deleted account (status 'deleted') can be seen but never changed.

Deactivated = any status that is not 'active', 'pending' or 'deleted'. Which enum label is written for it is looked up
in the database (see disabled_label).
"""
from __future__ import annotations

import psycopg

from web import db

VIEW_ROLES = {"admin": ("user", "employer", "admin"), "employer": ("user",)}
ACT_ROLES = {"admin": ("user", "employer"), "employer": ("user",)}
_PREFERRED_DISABLED = ("inactive", "suspended", "deactivated", "disabled", "blocked")
_disabled = None                                   # remembered once found; a missing label is looked up again next time

_COLS = ("u.id, u.full_name, u.email::text AS email, u.role::text AS role, u.status::text AS status, "
         "u.is_email_verified, u.created_at, u.last_login_at")


def _in(roles) -> str:
    """('user', 'employer'): built only from the fixed role names above, never from request data."""
    return "(" + ", ".join(f"'{r}'" for r in roles) + ")"


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def disabled_label():
    """The account_status label used for a deactivated account, or None when the type has none (run
    `python -m scripts.setup_user_management`)."""
    global _disabled
    if _disabled is None:
        with db.transaction() as c:
            labels = {r["label"] for r in c.execute(
                "SELECT unnest(enum_range(NULL::public.account_status))::text AS label").fetchall()}
        _disabled = next((x for x in _PREFERRED_DISABLED if x in labels), None)
    return _disabled


def list_page(actor_role: str, q: str, role: str, status: str, deleted: bool, limit: int, offset: int):
    """deleted=True lists only deleted accounts (read-only tab), otherwise everything else.
    status: '' | 'active' | 'pending' | 'inactive'.  role: '' | 'user' | 'employer' | 'admin'."""
    p = {"q": q, "like": _like(q), "role": role, "status": status, "limit": limit, "offset": offset}
    where = f"""u.role::text IN {_in(VIEW_ROLES[actor_role])}
        AND u.status::text {"=" if deleted else "<>"} 'deleted'
        AND (%(role)s = '' OR u.role::text = %(role)s)
        AND (%(status)s = ''
             OR (%(status)s IN ('active', 'pending') AND u.status::text = %(status)s)
             OR (%(status)s = 'inactive' AND u.status::text NOT IN ('active', 'pending', 'deleted')))
        AND (%(q)s = '' OR u.full_name ILIKE %(like)s ESCAPE '\\' OR u.email::text ILIKE %(like)s ESCAPE '\\')"""
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM public.users u WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"SELECT {_COLS} FROM public.users u WHERE {where} "
                         "ORDER BY u.created_at DESC, u.id LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
    return rows, total


def get_detail(actor_role: str, user_id):
    """Any account this person may SEE (deleted ones included), with its scan count."""
    return db.one(f"SELECT {_COLS}, (SELECT count(*) FROM public.detection_history h "
                  "WHERE h.user_id = u.id AND h.is_deleted = false) AS scan_count "
                  f"FROM public.users u WHERE u.id = %s AND u.role::text IN {_in(VIEW_ROLES[actor_role])}", (user_id,))


def rename(actor_role: str, actor_id, user_id, full_name: str):
    """Returns the account's email, or None when there is no such account this person may change."""
    row = db.one(f"UPDATE public.users u SET full_name = %s WHERE u.id = %s AND u.id <> %s "
                 f"AND u.role::text IN {_in(ACT_ROLES[actor_role])} AND u.status::text <> 'deleted' "
                 "RETURNING u.email::text AS email", (full_name, user_id, actor_id))
    return row["email"] if row else None


def set_status(actor_role: str, actor_id, user_id, activate: bool):
    """Returns ('ok', email) | ('not_found', None) | ('no_label', None) | ('conflict', reason).
    Deactivate an active or a pending account. Activate only a deactivated one whose email is verified
    (a pending account becomes active by verifying its email; an employer only by the approval)."""
    label = None if activate else disabled_label()
    if not activate and label is None:
        return "no_label", None
    with db.transaction() as c:
        row = c.execute("SELECT status::text AS status, email::text AS email, is_email_verified FROM public.users "
                        f"WHERE id = %s AND id <> %s AND role::text IN {_in(ACT_ROLES[actor_role])} "
                        "AND status::text <> 'deleted' FOR UPDATE", (user_id, actor_id)).fetchone()
        if not row:
            return "not_found", None
        cur = row["status"]
        if activate:
            if cur == "active":
                return "conflict", "This account is already active."
            if cur == "pending":
                return "conflict", "This account is still pending. It becomes active when its email is verified."
            if not row["is_email_verified"]:
                return "conflict", "This account has not verified its email yet."
            c.execute("UPDATE public.users SET status = 'active', failed_login_count = 0, locked_until = NULL "
                      "WHERE id = %s", (user_id,))
        else:
            if cur not in ("active", "pending"):
                return "conflict", "This account is already deactivated."
            c.execute("UPDATE public.users SET status = %s::public.account_status WHERE id = %s", (label, user_id))
    return "ok", row["email"]


def delete_account(actor_role: str, actor_id, user_id):
    """Returns ('ok', email, permanent) | ('not_found', None, False).
    An account that never verified its email is deleted for good, which frees the address. If the database refuses
    (it keeps rows that point at the account) it is marked 'deleted' instead, like every other account:
    no sign-in, kept for the records, never changed again."""
    with db.transaction() as c:
        row = c.execute("SELECT status::text AS status, email::text AS email, is_email_verified FROM public.users "
                        f"WHERE id = %s AND id <> %s AND role::text IN {_in(ACT_ROLES[actor_role])} "
                        "AND status::text <> 'deleted' FOR UPDATE", (user_id, actor_id)).fetchone()
        if not row:
            return "not_found", None, False
        if row["status"] == "pending" and not row["is_email_verified"]:
            c.execute("SAVEPOINT hard_delete")
            try:
                c.execute("UPDATE public.activity_logs SET user_id = NULL WHERE user_id = %s", (user_id,))
                c.execute("DELETE FROM public.users WHERE id = %s", (user_id,))
                c.execute("RELEASE SAVEPOINT hard_delete")
                return "ok", row["email"], True
            except psycopg.Error:
                c.execute("ROLLBACK TO SAVEPOINT hard_delete")        # keep the account as 'deleted' below
        c.execute("UPDATE public.users SET status = 'deleted' WHERE id = %s", (user_id,))
    return "ok", row["email"], False
