"""Trusted websites (Model layer).

whitelist_entries  : the trusted domains. scope 'user' = one person's own list, scope 'global' = set by an administrator.
whitelist_requests : a user asks for a domain to be trusted; an employer or an administrator approves or rejects it.
Approving a request adds the domain to the REQUESTER's own list only (never to the global one).
"""
from __future__ import annotations

from web import db

_ENTRY = ("SELECT e.id, e.domain, e.scope, e.created_at, e.added_by, u.full_name AS added_by_name, "
          "u.email::text AS added_by_email "
          "FROM public.whitelist_entries e LEFT JOIN public.users u ON u.id = e.added_by")

_REQUEST = """
SELECT r.id, r.domain, r.reason, r.risk_score, r.risk_level, r.status, r.review_note, r.created_at, r.reviewed_at,
       u.email::text AS requester_email, u.full_name AS requester_name, rv.full_name AS reviewed_by_name
FROM public.whitelist_requests r
JOIN public.users u ON u.id = r.user_id
LEFT JOIN public.users rv ON rv.id = r.reviewed_by
"""


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ---- trusted domains -------------------------------------------------------------------------------------------

def list_entries(scope: str, user_id, limit: int, offset: int):
    """scope 'global' = the administrator's list, 'user' = this person's own list."""
    where = "e.scope = 'global'" if scope == "global" else "e.scope = 'user' AND e.user_id = %(uid)s"
    p = {"uid": user_id, "limit": limit, "offset": offset}
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM public.whitelist_entries e WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"{_ENTRY} WHERE {where} ORDER BY e.created_at DESC, e.domain LIMIT %(limit)s OFFSET %(offset)s",
                         p).fetchall()
    return rows, total


def trusted_scope(user_id, host: str):
    """'global' or 'user' when this host (or a parent domain of it) is trusted for this person, else None."""
    row = db.one(
        "SELECT scope FROM public.whitelist_entries "
        "WHERE (scope = 'global' OR (scope = 'user' AND user_id = %(uid)s)) "
        "AND (domain = %(h)s::text OR right(%(h)s::text, char_length(domain) + 1) = '.' || domain) "
        "ORDER BY (scope = 'global') DESC LIMIT 1", {"uid": user_id, "h": host})
    return row["scope"] if row else None


def add_global(admin_id, domain: str):
    """Adds a domain to the global list. Returns {'id', 'created_at'}, or None when it was already there."""
    return db.one("INSERT INTO public.whitelist_entries (scope, domain, added_by) VALUES ('global', %s, %s) "
                  "ON CONFLICT DO NOTHING RETURNING id, created_at", (domain, admin_id))


def remove(entry_id, scope: str, user_id) -> bool:
    """Deletes one entry. A user can only delete from their own list, an administrator only from the global one."""
    if scope == "global":
        row = db.one("DELETE FROM public.whitelist_entries WHERE id = %s AND scope = 'global' RETURNING id", (entry_id,))
    else:
        row = db.one("DELETE FROM public.whitelist_entries WHERE id = %s AND scope = 'user' AND user_id = %s "
                     "RETURNING id", (entry_id, user_id))
    return row is not None


# ---- requests --------------------------------------------------------------------------------------------------

def create_request(user_id, domain: str, reason, risk_score, risk_level: str):
    """Returns the new row, or None when this person already has a pending request for the domain."""
    return db.one("INSERT INTO public.whitelist_requests (user_id, domain, reason, risk_score, risk_level) "
                  "VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING "
                  "RETURNING id, domain, reason, risk_score, risk_level, status, review_note, created_at, reviewed_at",
                  (user_id, domain, reason, risk_score, risk_level))


def my_requests(user_id, limit: int = 20):
    """Pending requests, and rejected ones from the last 30 days, so the person can see what happened."""
    with db.transaction() as c:
        return c.execute(
            "SELECT id, domain, reason, risk_score, risk_level, status, review_note, created_at, reviewed_at "
            "FROM public.whitelist_requests WHERE user_id = %s AND (status = 'pending' "
            "OR (status = 'rejected' AND reviewed_at > now() - interval '30 days')) "
            "ORDER BY created_at DESC LIMIT %s", (user_id, limit)).fetchall()


def list_requests(status: str, q: str, limit: int, offset: int):
    p = {"status": status, "q": q, "like": _like(q), "limit": limit, "offset": offset}
    where = """(%(status)s = '' OR r.status = %(status)s)
               AND (%(q)s = '' OR r.domain ILIKE %(like)s ESCAPE '\\' OR u.email::text ILIKE %(like)s ESCAPE '\\')"""
    with db.transaction() as c:
        total = c.execute("SELECT count(*) AS n FROM public.whitelist_requests r "
                          f"JOIN public.users u ON u.id = r.user_id WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"{_REQUEST} WHERE {where} ORDER BY (r.status = 'pending') DESC, r.created_at DESC "
                         "LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
        counts = {r["s"]: r["n"] for r in c.execute(
            "SELECT status AS s, count(*) AS n FROM public.whitelist_requests GROUP BY 1").fetchall()}
    return rows, total, {"pending": counts.get("pending", 0), "approved": counts.get("approved", 0),
                         "rejected": counts.get("rejected", 0)}


def get_request(req_id):
    return db.one(f"{_REQUEST} WHERE r.id = %s", (req_id,))


def review_request(req_id, reviewer_id, decision: str, note: str) -> str:
    """decision: 'approve' | 'reject'. Only a pending request can be reviewed.
    Returns 'ok', 'not_found' or 'conflict' (already reviewed)."""
    with db.transaction() as c:
        row = c.execute("SELECT user_id, domain, status FROM public.whitelist_requests WHERE id = %s FOR UPDATE",
                        (req_id,)).fetchone()
        if not row:
            return "not_found"
        if row["status"] != "pending":
            return "conflict"
        new = "approved" if decision == "approve" else "rejected"
        if new == "approved":
            c.execute("INSERT INTO public.whitelist_entries (scope, user_id, domain, added_by, request_id) "
                      "VALUES ('user', %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                      (row["user_id"], row["domain"], row["user_id"], req_id))
        c.execute("UPDATE public.whitelist_requests SET status = %s, review_note = %s, reviewed_by = %s, "
                  "reviewed_at = now() WHERE id = %s", (new, note or None, reviewer_id, req_id))
    return "ok"
