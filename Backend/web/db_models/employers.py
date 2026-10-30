"""Employer verification (Model layer). Approving an employer is the ONLY place an account becomes 'employer'."""
from __future__ import annotations

from web import db

_SELECT = """
SELECT v.id, v.user_id, u.full_name AS name, u.email::text AS email, v.company_name, v.company_registration_no,
       v.verification_status::text AS status, v.remarks, v.submitted_at, v.reviewed_at,
       rv.full_name AS reviewed_by_name, u.role::text AS role, u.status::text AS account_status,
       u.is_email_verified AS email_verified
FROM public.employer_verifications v
JOIN public.users u ON u.id = v.user_id
LEFT JOIN public.users rv ON rv.id = v.reviewed_by
"""


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def list_page(status: str, q: str, limit: int, offset: int):
    p = {"status": status, "q": q, "like": _like(q), "limit": limit, "offset": offset}
    where = """(%(status)s = '' OR v.verification_status = NULLIF(%(status)s, '')::public.verification_status)
               AND (%(q)s = '' OR u.full_name ILIKE %(like)s ESCAPE '\\' OR u.email::text ILIKE %(like)s ESCAPE '\\'
                    OR v.company_name ILIKE %(like)s ESCAPE '\\')"""
    with db.transaction() as c:
        total = c.execute("SELECT count(*) AS n FROM public.employer_verifications v "
                          f"JOIN public.users u ON u.id = v.user_id WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"{_SELECT} WHERE {where} ORDER BY (v.verification_status = 'pending') DESC, "
                         "v.submitted_at DESC LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
        counts = {r["s"]: r["n"] for r in c.execute(
            "SELECT verification_status::text AS s, count(*) AS n FROM public.employer_verifications GROUP BY 1").fetchall()}
    return rows, total, {"pending": counts.get("pending", 0), "approved": counts.get("approved", 0),
                         "rejected": counts.get("rejected", 0)}


def get(v_id):
    return db.one(f"{_SELECT} WHERE v.id = %s", (v_id,))


def review(v_id, reviewer_id, decision: str, remarks: str) -> str:
    """decision: 'approved' | 'rejected'. Works from any current status, so an administrator can also correct an
    earlier decision (FR 3.4.6.7). Returns 'ok', 'not_found', 'forbidden' or 'not_verified'."""
    with db.transaction() as c:
        row = c.execute(
            "SELECT v.user_id, u.role::text AS role, u.status::text AS account_status, u.is_email_verified "
            "FROM public.employer_verifications v JOIN public.users u ON u.id = v.user_id "
            "WHERE v.id = %s FOR UPDATE OF v, u", (v_id,)).fetchone()
        if not row:
            return "not_found"
        if row["role"] == "admin":
            return "forbidden"                                   # an administrator is never changed here
        uid = row["user_id"]
        if decision == "approved":
            if not row["is_email_verified"] or row["account_status"] != "active":
                return "not_verified"
            c.execute("SELECT set_config('app.privileged_role_write', 'on', true)")   # this transaction only
            c.execute("UPDATE public.users SET role = 'employer' WHERE id = %s AND role = 'user'", (uid,))
        else:
            c.execute("UPDATE public.users SET role = 'user' WHERE id = %s AND role = 'employer'", (uid,))
        c.execute("UPDATE public.employer_verifications SET verification_status = %s::public.verification_status, "
                  "remarks = %s, reviewed_by = %s, reviewed_at = now() WHERE id = %s",
                  (decision, remarks or None, reviewer_id, v_id))
        c.execute("UPDATE public.approval_requests SET status = %s::public.verification_status, reviewer_id = %s "
                  "WHERE verification_id = %s", (decision, reviewer_id, v_id))
        c.execute("UPDATE public.sessions SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL", (uid,))
    return "ok"
