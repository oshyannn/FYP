"""The global threat URL list (Model layer). Entries come from detection results (models/scans.py) as
'pending_review' and become visible to everyone once an authorised person approves them."""
from __future__ import annotations

from web import db

_COLS = ("id, url, domain, risk_level::text AS risk_level, risk_score, threat_type::text AS threat_type, "
         "status::text AS status, detection_count, created_at, last_verified_at")
_ONLY_THREATS = "risk_level IN ('suspicious', 'malicious')"


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def list_page(status: str, q: str, threat_type: str, limit: int, offset: int):
    p = {"status": status, "q": q, "like": _like(q), "type": threat_type, "limit": limit, "offset": offset}
    where = f"""{_ONLY_THREATS}
                AND (%(status)s = '' OR status = NULLIF(%(status)s, '')::public.url_status)
                AND (%(q)s = '' OR url ILIKE %(like)s ESCAPE '\\')
                AND (%(type)s = '' OR threat_type = NULLIF(%(type)s, '')::public.threat_type)"""
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM public.global_urls WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"SELECT {_COLS} FROM public.global_urls WHERE {where} "
                         "ORDER BY last_verified_at DESC LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
    return rows, total


def stats() -> dict:
    row = db.one(f"""SELECT
        count(*) FILTER (WHERE status = 'active') AS total,
        count(*) FILTER (WHERE status = 'active' AND threat_type = 'phishing') AS phishing,
        count(*) FILTER (WHERE status = 'active' AND threat_type = 'malware') AS malware,
        count(*) FILTER (WHERE status = 'active' AND risk_level = 'suspicious') AS suspicious,
        count(*) FILTER (WHERE status = 'pending_review') AS pending
        FROM public.global_urls WHERE {_ONLY_THREATS}""")
    return {k: int(v) for k, v in row.items()}


def get(gid):
    return db.one(f"SELECT {_COLS} FROM public.global_urls WHERE id = %s AND {_ONLY_THREATS}", (gid,))


def review(gid, decision: str, is_admin: bool) -> str:
    """decision: 'approve' (-> active) or 'remove' (-> revoked).
    An employer may only act on pending entries; an administrator may also remove active ones and reinstate
    removed ones. Returns 'ok', 'not_found', 'forbidden' or 'conflict'."""
    with db.transaction() as c:
        row = c.execute("SELECT status::text AS status FROM public.global_urls WHERE id = %s FOR UPDATE", (gid,)).fetchone()
        if not row:
            return "not_found"
        cur = row["status"]
        if decision == "approve":
            if cur == "active":
                return "conflict"
            if cur == "revoked" and not is_admin:
                return "forbidden"
            new = "active"
        else:
            if cur == "revoked":
                return "conflict"
            if cur == "active" and not is_admin:
                return "forbidden"
            new = "revoked"
        c.execute("UPDATE public.global_urls SET status = %s::public.url_status WHERE id = %s", (new, gid))
    return "ok"
