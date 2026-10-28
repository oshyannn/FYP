"""Scan history (Model layer). Every query is scoped to the owner, so one user can never read or delete
another user's records."""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from psycopg.types.json import Jsonb

from web import db

_LIST_COLS = ("h.id, h.url, h.domain, h.scan_type::text AS scan_type, h.user_action::text AS user_action, "
              "h.scanned_at, h.risk_level::text AS risk_level, h.risk_score")


def canonical_url(url: str) -> str:
    """scheme://host[:port]/path. Query strings and fragments can carry tokens, and user info can carry passwords:
    none of them are ever hashed or written to the shared threat list."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{host}{port}{parts.path or '/'}"


def url_hash(canon: str) -> str:
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def record_scan(*, user_id, url: str, canon: str, domain: str, scan_type: str, level: str, score: float,
                threat_type: str, analysis: dict) -> dict:
    """Saves one scan. Suspicious/malicious URLs also go to the shared threat list (as 'pending_review', so an
    authorised person confirms them); safe and unknown results stay in the user's own history only."""
    h = url_hash(canon)
    with db.transaction() as c:
        gid = None
        if level in ("suspicious", "malicious"):
            gid = c.execute(
                """INSERT INTO public.global_urls
                       (url, normalized_url, url_hash, domain, risk_level, risk_score, threat_type, status, created_by)
                   VALUES (%(canon)s, %(canon)s, %(h)s, %(domain)s, %(level)s::public.risk_level, %(score)s,
                           %(threat)s::public.threat_type, 'pending_review', %(uid)s)
                   ON CONFLICT (url_hash) DO UPDATE SET
                       risk_level  = CASE WHEN EXCLUDED.risk_score > public.global_urls.risk_score
                                          THEN EXCLUDED.risk_level ELSE public.global_urls.risk_level END,
                       threat_type = CASE WHEN EXCLUDED.risk_score > public.global_urls.risk_score
                                          THEN EXCLUDED.threat_type ELSE public.global_urls.threat_type END,
                       risk_score  = GREATEST(public.global_urls.risk_score, EXCLUDED.risk_score)
                   RETURNING id""",
                {"canon": canon, "h": h, "domain": domain, "level": level, "score": score,
                 "threat": threat_type, "uid": user_id}).fetchone()["id"]
        row = c.execute(
            """INSERT INTO public.detection_history
                   (user_id, global_url_id, url, url_hash, domain, scan_type, risk_level, risk_score, analysis)
               VALUES (%(uid)s, %(gid)s, %(url)s, %(h)s, %(domain)s, %(stype)s::public.scan_type,
                       %(level)s::public.risk_level, %(score)s, %(analysis)s)
               RETURNING id, scanned_at""",
            {"uid": user_id, "gid": gid, "url": url, "h": h, "domain": domain, "stype": scan_type,
             "level": level, "score": score, "analysis": Jsonb(analysis)}).fetchone()
    return {"id": row["id"], "scanned_at": row["scanned_at"]}


def list_page(user_id, q: str, level: str, scan_type: str, limit: int, offset: int):
    params = {"uid": user_id, "q": q, "like": _like(q), "level": level, "stype": scan_type,
              "limit": limit, "offset": offset}
    where = """h.user_id = %(uid)s AND h.is_deleted = false
               AND (%(q)s = '' OR h.url ILIKE %(like)s ESCAPE '\\')
               AND (%(level)s = '' OR h.risk_level = NULLIF(%(level)s, '')::public.risk_level)
               AND (%(stype)s = '' OR h.scan_type = NULLIF(%(stype)s, '')::public.scan_type)"""
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM public.detection_history h WHERE {where}", params).fetchone()["n"]
        rows = c.execute(f"SELECT {_LIST_COLS} FROM public.detection_history h WHERE {where} "
                         "ORDER BY h.scanned_at DESC LIMIT %(limit)s OFFSET %(offset)s", params).fetchall()
    return rows, total


def get_one(user_id, scan_id):
    return db.one(
        f"SELECT {_LIST_COLS}, h.analysis, g.threat_type::text AS threat_type, g.status::text AS list_status, "
        "g.detection_count FROM public.detection_history h "
        "LEFT JOIN public.global_urls g ON g.id = h.global_url_id "
        "WHERE h.id = %s AND h.user_id = %s AND h.is_deleted = false", (scan_id, user_id))


def delete_many(user_id, ids: list) -> int:
    """Soft delete (is_deleted = true). Returns how many of the caller's own records were removed."""
    with db.transaction() as c:
        cur = c.execute("UPDATE public.detection_history SET is_deleted = true "
                        "WHERE user_id = %s AND is_deleted = false AND id = ANY(%s::uuid[])",
                        (user_id, [str(i) for i in ids]))
        return cur.rowcount


def set_action(user_id, scan_id, action: str) -> bool:
    """Records what the user chose after a warning (proceeded / blocked / reported). Owner only."""
    row = db.one("UPDATE public.detection_history SET user_action = %s::public.user_action "
                 "WHERE id = %s AND user_id = %s AND is_deleted = false RETURNING id", (action, scan_id, user_id))
    return row is not None
