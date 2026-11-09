"""Threat URL submissions (Model layer). An employer reports a URL; an administrator approves it (it is then published
to the Global Threat List, public.global_urls, as 'active') or rejects it."""
from __future__ import annotations

from web import db
from web.db_models import scans

_COLS = ("s.id, s.url, s.domain, s.category, s.risk_score, s.notes, s.review_status, s.review_note, s.created_at, "
         "s.reviewed_at")

_ADMIN = f"""
SELECT {_COLS}, u.email::text AS submitted_by_email, u.full_name AS submitted_by_name, rv.full_name AS reviewed_by_name
FROM public.threat_submissions s
JOIN public.users u ON u.id = s.submitted_by
LEFT JOIN public.users rv ON rv.id = s.reviewed_by
"""


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def publish_values(category: str, score: float):
    """(threat_type, risk_level) used when an approved submission is published. 'Suspicious' has no threat type of
    its own; everything else is 'malicious' from a score of 70, the same split the screens colour by."""
    if category == "suspicious":
        return "unknown", "suspicious"
    return category, ("malicious" if score >= 70 else "suspicious")


def create(user_id, url: str, canon: str, domain: str, category: str, score: float, notes: str):
    """Returns ('ok', row) | ('listed', None) when the URL is already on the active list |
    ('pending', None) when somebody already submitted it and it is waiting for review."""
    h = scans.url_hash(canon)
    with db.transaction() as c:
        if c.execute("SELECT 1 FROM public.global_urls WHERE url_hash = %s AND status = 'active'", (h,)).fetchone():
            return "listed", None
        row = c.execute(
            "INSERT INTO public.threat_submissions (submitted_by, url, domain, url_hash, category, risk_score, notes) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING "
            "RETURNING id, url, domain, category, risk_score, notes, review_status, review_note, created_at, reviewed_at",
            (user_id, canon, domain, h, category, score, notes)).fetchone()
        if row is None:
            return "pending", None
    return "ok", row


def list_mine(user_id, limit: int, offset: int):
    with db.transaction() as c:
        total = c.execute("SELECT count(*) AS n FROM public.threat_submissions WHERE submitted_by = %s",
                          (user_id,)).fetchone()["n"]
        rows = c.execute(f"SELECT {_COLS} FROM public.threat_submissions s WHERE s.submitted_by = %s "
                         "ORDER BY s.created_at DESC LIMIT %s OFFSET %s", (user_id, limit, offset)).fetchall()
        pending = c.execute("SELECT count(*) AS n FROM public.threat_submissions "
                            "WHERE submitted_by = %s AND review_status = 'pending'", (user_id,)).fetchone()["n"]
    return rows, total, {"pending": pending}


def list_page(status: str, q: str, limit: int, offset: int):
    p = {"status": status, "q": q, "like": _like(q), "limit": limit, "offset": offset}
    where = """(%(status)s = '' OR s.review_status = %(status)s)
               AND (%(q)s = '' OR s.url ILIKE %(like)s ESCAPE '\\' OR u.email::text ILIKE %(like)s ESCAPE '\\')"""
    with db.transaction() as c:
        total = c.execute("SELECT count(*) AS n FROM public.threat_submissions s "
                          f"JOIN public.users u ON u.id = s.submitted_by WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"{_ADMIN} WHERE {where} ORDER BY (s.review_status = 'pending') DESC, s.created_at DESC "
                         "LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
        counts = {r["s"]: r["n"] for r in c.execute(
            "SELECT review_status AS s, count(*) AS n FROM public.threat_submissions GROUP BY 1").fetchall()}
    pending, approved, rejected = (counts.get(k, 0) for k in ("pending", "approved", "rejected"))
    return rows, total, {"total": pending + approved + rejected, "pending": pending,
                         "reviewed": approved + rejected, "approved": approved, "rejected": rejected}


def get(sub_id):
    return db.one(f"{_ADMIN} WHERE s.id = %s", (sub_id,))


def review(sub_id, reviewer_id, decision: str, note: str, match_scope: str | None = None) -> str:
    """decision: 'approve' (publish to the Global Threat List) | 'reject'. Only a pending submission can be reviewed.
    Returns 'ok', 'not_found' or 'conflict' (already reviewed)."""
    with db.transaction() as c:
        row = c.execute("SELECT url, domain, url_hash, category, risk_score, review_status, submitted_by "
                        "FROM public.threat_submissions WHERE id = %s FOR UPDATE", (sub_id,)).fetchone()
        if not row:
            return "not_found"
        if row["review_status"] != "pending":
            return "conflict"
        gid = None
        if decision == "approve":
            ttype, level = publish_values(row["category"], float(row["risk_score"]))
            gid = c.execute(
                """INSERT INTO public.global_urls
                       (url, normalized_url, url_hash, domain, risk_level, risk_score, threat_type, status, created_by, match_scope)
                   VALUES (%(url)s, %(url)s, %(h)s, %(domain)s, %(level)s::public.risk_level, %(score)s,
                           %(ttype)s::public.threat_type, 'active', %(uid)s, coalesce(%(scope)s::text, 'auto'))
                   ON CONFLICT (url_hash) DO UPDATE SET
                       status      = 'active',
                       match_scope = coalesce(%(scope)s::text, public.global_urls.match_scope),
                       risk_level  = EXCLUDED.risk_level,
                       threat_type = EXCLUDED.threat_type,
                       risk_score  = GREATEST(public.global_urls.risk_score, EXCLUDED.risk_score)
                   RETURNING id""",
                {"url": row["url"], "h": row["url_hash"], "domain": row["domain"], "level": level,
                 "score": row["risk_score"], "ttype": ttype, "uid": row["submitted_by"], "scope": match_scope}).fetchone()["id"]
        c.execute("UPDATE public.threat_submissions SET review_status = %s, review_note = %s, reviewed_by = %s, "
                  "reviewed_at = now(), global_url_id = %s WHERE id = %s",
                  ("approved" if decision == "approve" else "rejected", note or None, reviewer_id, gid, sub_id))
    return "ok"
