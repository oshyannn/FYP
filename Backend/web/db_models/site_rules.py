"""A person's own decision per website (Model layer): public.url_lists, list_type 'allow' | 'block'.

One row per person and website (unique user_id + url_hash). The website is stored as 'https://<host>/' with a leading
'www.' removed, so www.example.com and example.com are the same rule. Temporary choices ("just this once", "for an hour")
are never stored here: the extension keeps those itself.
"""
from __future__ import annotations

from web import db
from web.db_models import scans


def canon(host: str) -> str:
    return f"https://{host}/"


def list_rules(user_id):
    with db.transaction() as c:
        return c.execute("SELECT id, url, list_type::text AS rule, note, created_at FROM public.url_lists "
                         "WHERE user_id = %s AND status = 'active' ORDER BY created_at DESC", (user_id,)).fetchall()


def set_rule(user_id, host: str, rule: str, note):
    """Adds or changes the rule for a website. Returns the row."""
    c = canon(host)
    return db.one(
        "INSERT INTO public.url_lists (user_id, url, url_hash, list_type, note) "
        "VALUES (%s, %s, %s, %s::public.list_type, %s) "
        "ON CONFLICT (user_id, url_hash) DO UPDATE SET list_type = EXCLUDED.list_type, status = 'active', "
        "note = coalesce(EXCLUDED.note, public.url_lists.note), updated_at = now() "
        "RETURNING id, url, list_type::text AS rule, note, created_at",
        (user_id, c, scans.url_hash(c), rule, note))


def delete(user_id, rule_id) -> bool:
    return db.one("DELETE FROM public.url_lists WHERE id = %s AND user_id = %s RETURNING id", (rule_id, user_id)) is not None


def delete_host(user_id, host: str) -> bool:
    return db.one("DELETE FROM public.url_lists WHERE user_id = %s AND url_hash = %s RETURNING id",
                  (user_id, scans.url_hash(canon(host)))) is not None
