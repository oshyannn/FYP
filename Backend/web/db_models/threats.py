"""The global threat URL list (Model layer). Entries come from detection results (models/scans.py) as
'pending_review' and become visible to everyone once an authorised person approves them."""
from __future__ import annotations

from web import db

_COLS = ("id, url, domain, risk_level::text AS risk_level, risk_score, threat_type::text AS threat_type, "
         "status::text AS status, detection_count, created_at, last_verified_at, match_scope, notes")
_ONLY_THREATS = "risk_level IN ('suspicious', 'malicious')"

_SORTS = {
    "newest": "last_verified_at DESC",
    "oldest": "last_verified_at ASC",
    "detections": "detection_count DESC, last_verified_at DESC",
    "url": "url ASC",
}


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def list_page(status: str, q: str, threat_type: str, limit: int, offset: int,
              risk_level: str = "", sort: str = "newest"):
    order = _SORTS.get(sort, "last_verified_at DESC")
    p = {"status": status, "q": q, "like": _like(q), "type": threat_type,
         "level": risk_level, "limit": limit, "offset": offset}
    where = f"""{_ONLY_THREATS}
                AND (%(status)s = '' OR status = NULLIF(%(status)s, '')::public.url_status)
                AND (%(q)s = '' OR url ILIKE %(like)s ESCAPE '\\')
                AND (%(type)s = '' OR threat_type = NULLIF(%(type)s, '')::public.threat_type)
                AND (%(level)s = '' OR risk_level = NULLIF(%(level)s, '')::public.risk_level)"""
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM public.global_urls WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"SELECT {_COLS} FROM public.global_urls WHERE {where} "
                         f"ORDER BY {order} LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
    return rows, total


def stats() -> dict:
    row = db.one(f"""SELECT
        count(*) FILTER (WHERE status = 'active') AS total,
        count(*) FILTER (WHERE status = 'active' AND threat_type = 'phishing') AS phishing,
        count(*) FILTER (WHERE status = 'active' AND threat_type = 'malware') AS malware,
        count(*) FILTER (WHERE status = 'active' AND risk_level = 'suspicious') AS suspicious,
        count(*) FILTER (WHERE status = 'pending_review') AS pending,
        count(*) FILTER (WHERE status = 'revoked') AS revoked
        FROM public.global_urls WHERE {_ONLY_THREATS}""")
    return {k: int(v) for k, v in row.items()}


def create_manual(user_id, url: str, canon: str, url_hash: str, domain: str,
                  threat_type: str, is_malicious: bool, match_scope: str, notes: str | None):
    """Manually adds a threat URL directly as active. Returns ('ok', row) or ('duplicate', None)."""
    level = "malicious" if is_malicious else "suspicious"
    score = 100.0 if is_malicious else 50.0
    with db.transaction() as c:
        existing = c.execute("SELECT id, status::text AS status FROM public.global_urls WHERE url_hash = %s", (url_hash,)).fetchone()
        if existing:
            return "duplicate", None
        row = c.execute(
            f"""INSERT INTO public.global_urls
                   (url, normalized_url, url_hash, domain, risk_level, risk_score, threat_type, status, match_scope, notes, created_by)
               VALUES (%s, %s, %s, %s, %s::public.risk_level, %s, %s::public.threat_type, 'active', %s, %s, %s)
               RETURNING {_COLS}""",
            (canon, canon, url_hash, domain, level, score, threat_type, match_scope, notes, user_id),
        ).fetchone()
    return "ok", row


def update_entry(gid, threat_type: str | None, is_malicious: bool | None,
                 match_scope: str | None, notes: str | None, url: str | None = None,
                 canon: str | None = None, url_hash: str | None = None, domain: str | None = None) -> str:
    """Modifies an existing threat entry. Returns 'ok', 'not_found', or 'duplicate'."""
    with db.transaction() as c:
        row = c.execute("SELECT id FROM public.global_urls WHERE id = %s FOR UPDATE", (gid,)).fetchone()
        if not row:
            return "not_found"
        if url_hash:
            dup = c.execute("SELECT 1 FROM public.global_urls WHERE url_hash = %s AND id <> %s", (url_hash, gid)).fetchone()
            if dup:
                return "duplicate"
        level = ("malicious" if is_malicious else "suspicious") if is_malicious is not None else None
        score = (100.0 if is_malicious else 50.0) if is_malicious is not None else None
        c.execute(
            """UPDATE public.global_urls
               SET url = coalesce(%s, url),
                   normalized_url = coalesce(%s, normalized_url),
                   url_hash = coalesce(%s, url_hash),
                   domain = coalesce(%s, domain),
                   threat_type = coalesce(%s::public.threat_type, threat_type),
                   risk_level = coalesce(%s::public.risk_level, risk_level),
                   risk_score = coalesce(%s, risk_score),
                   match_scope = coalesce(%s, match_scope),
                   notes = coalesce(%s, notes)
               WHERE id = %s""",
            (canon, canon, url_hash, domain, threat_type, level, score, match_scope, notes, gid),
        )
    return "ok"


def delete_entry(gid) -> bool:
    """Deletes a threat entry (detaches any detection_history references first)."""
    with db.transaction() as c:
        c.execute("UPDATE public.detection_history SET global_url_id = NULL WHERE global_url_id = %s", (gid,))
        row = c.execute("DELETE FROM public.global_urls WHERE id = %s RETURNING id", (gid,)).fetchone()
    return row is not None


def get(gid):
    return db.one(f"SELECT {_COLS} FROM public.global_urls WHERE id = %s AND {_ONLY_THREATS}", (gid,))


def review(gid, decision: str, is_admin: bool, match_scope: str | None = None) -> str:
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
        c.execute("UPDATE public.global_urls SET status = %s::public.url_status, "
                  "match_scope = coalesce(%s::text, match_scope) WHERE id = %s", (new, match_scope if decision == "approve" else None, gid))
    return "ok"


def set_scope(gid, scope: str) -> bool:
    """'auto' (a front-page entry covers the whole domain) or 'exact' (only this address). False when there is no such entry."""
    row = db.one("UPDATE public.global_urls SET match_scope = %s WHERE id = %s AND risk_level IN ('suspicious', 'malicious') "
                 "RETURNING id", (scope, gid))
    return row is not None
