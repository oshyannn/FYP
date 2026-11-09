"""A person's starred websites (Model layer): public.saved_urls. Every query is scoped to the owner."""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

from web import db

_COLS = "id, url, domain, title, note, risk_level::text AS risk_level, risk_score, checked_at, created_at"


def clean_url(url: str) -> str:
    """scheme://host[:port]/path?query. Unlike the shared threat list, a person's own list keeps the query string (a
    video or an article is only found again with it); the fragment and any user info (passwords) are dropped."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port else ""
    q = f"?{p.query}" if p.query else ""
    return f"{p.scheme.lower()}://{host}{port}{p.path or '/'}{q}"


def url_hash(clean: str) -> str:
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def list_page(user_id, q: str, limit: int, offset: int):
    p = {"uid": user_id, "q": q, "like": _like(q), "limit": limit, "offset": offset}
    where = """user_id = %(uid)s AND (%(q)s = '' OR url ILIKE %(like)s ESCAPE '\\'
               OR coalesce(title, '') ILIKE %(like)s ESCAPE '\\' OR coalesce(note, '') ILIKE %(like)s ESCAPE '\\')"""
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM public.saved_urls WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"SELECT {_COLS} FROM public.saved_urls WHERE {where} "
                         "ORDER BY created_at DESC LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
    return rows, total


def get(user_id, saved_id):
    return db.one(f"SELECT {_COLS} FROM public.saved_urls WHERE id = %s AND user_id = %s", (saved_id, user_id))


def lookup(user_id, clean: str):
    return db.one(f"SELECT {_COLS} FROM public.saved_urls WHERE user_id = %s AND url_hash = %s",
                  (user_id, url_hash(clean)))


def save(user_id, clean: str, domain: str, title, note, level: str, score: float, checked: bool):
    """Adds the website, or (when it is already saved) refreshes its title / note / verdict. Returns (row, created)."""
    row = db.one(
        "INSERT INTO public.saved_urls (user_id, url, url_hash, domain, title, note, risk_level, risk_score, checked_at) "
        "VALUES (%(uid)s, %(url)s, %(h)s, %(domain)s, %(title)s, %(note)s, %(level)s::public.risk_level, %(score)s, "
        "CASE WHEN %(checked)s THEN now() END) "
        "ON CONFLICT (user_id, url_hash) DO UPDATE SET "
        "  title = coalesce(EXCLUDED.title, public.saved_urls.title), "
        "  note = coalesce(EXCLUDED.note, public.saved_urls.note), "
        "  risk_level = CASE WHEN %(checked)s THEN EXCLUDED.risk_level ELSE public.saved_urls.risk_level END, "
        "  risk_score = CASE WHEN %(checked)s THEN EXCLUDED.risk_score ELSE public.saved_urls.risk_score END, "
        "  checked_at = CASE WHEN %(checked)s THEN now() ELSE public.saved_urls.checked_at END "
        f"RETURNING {_COLS}, (xmax = 0) AS created",
        {"uid": user_id, "url": clean, "h": url_hash(clean), "domain": domain, "title": title, "note": note,
         "level": level, "score": score, "checked": checked})
    created = row.pop("created")
    return row, created


def update_verdict(user_id, saved_id, level: str, score: float):
    return db.one(
        "UPDATE public.saved_urls SET risk_level = %s::public.risk_level, risk_score = %s, checked_at = now() "
        f"WHERE id = %s AND user_id = %s RETURNING {_COLS}", (level, score, saved_id, user_id))


def update_note(user_id, saved_id, note):
    return db.one(f"UPDATE public.saved_urls SET note = %s WHERE id = %s AND user_id = %s RETURNING {_COLS}",
                  (note, saved_id, user_id))


def delete(user_id, saved_id) -> bool:
    return db.one("DELETE FROM public.saved_urls WHERE id = %s AND user_id = %s RETURNING id", (saved_id, user_id)) is not None


def delete_url(user_id, clean: str) -> bool:
    return db.one("DELETE FROM public.saved_urls WHERE user_id = %s AND url_hash = %s RETURNING id",
                  (user_id, url_hash(clean))) is not None
