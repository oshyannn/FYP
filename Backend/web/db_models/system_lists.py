"""The detector's own lists (Model layer): public.detection_lists, managed by administrators.

whitelist    domains the detector trusts (on top of the Tranco top sites)
not_trusted  domains removed from the Tranco part of the trusted list (a popular site that should not be trusted)
blacklist    domains that are always Malicious
adult_manual domains added to the adult-site list

Removing an entry only switches it off (is_active = false): the row stays, so the history is kept and
`sync_to_supabase lists` (which adds file entries that are missing) does not bring it back.
"""
from __future__ import annotations

from web import db

TYPES = ("whitelist", "not_trusted", "blacklist", "adult_manual")
_COLS = ("l.id, l.list_type::text AS list_type, l.value, l.note, l.is_active, l.created_at, "
         "u.full_name AS added_by_name, u.email::text AS added_by_email")


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def list_page(list_type: str, q: str, include_inactive: bool, limit: int, offset: int):
    p = {"type": list_type, "q": q, "like": _like(q), "all": include_inactive, "limit": limit, "offset": offset}
    where = """l.list_type = %(type)s::public.detection_list_type
               AND (%(all)s OR l.is_active)
               AND (%(q)s = '' OR l.value ILIKE %(like)s ESCAPE '\\')"""
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM public.detection_lists l WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"SELECT {_COLS} FROM public.detection_lists l LEFT JOIN public.users u ON u.id = l.created_by "
                         f"WHERE {where} ORDER BY l.created_at DESC, l.value LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
    return rows, total


def add(list_type: str, domain: str, note, admin_id) -> str:
    """'added', 'reactivated' (it was switched off) or 'exists' (already active)."""
    with db.transaction() as c:
        row = c.execute("SELECT id, is_active FROM public.detection_lists "
                        "WHERE list_type = %s::public.detection_list_type AND value = %s FOR UPDATE",
                        (list_type, domain)).fetchone()
        if row and row["is_active"]:
            return "exists"
        if row:
            c.execute("UPDATE public.detection_lists SET is_active = true, note = coalesce(%s, note), updated_at = now() "
                      "WHERE id = %s", (note, row["id"]))
            return "reactivated"
        c.execute("INSERT INTO public.detection_lists (list_type, value, note, created_by) "
                  "VALUES (%s::public.detection_list_type, %s, %s, %s)", (list_type, domain, note, admin_id))
    return "added"


def deactivate(entry_id):
    """Switches one entry off. Returns its (list_type, value), or None when it does not exist / is already off."""
    return db.one("UPDATE public.detection_lists SET is_active = false, updated_at = now() "
                  "WHERE id = %s AND is_active AND list_type::text = ANY(%s) RETURNING list_type::text AS list_type, value",
                  (entry_id, list(TYPES)))


def lookup(domain: str) -> dict:
    """Why a domain is (not) trusted: its Tranco rank, the cut-off in use, and its entries in the managed lists."""
    with db.transaction() as c:
        rank = c.execute("SELECT rank FROM public.trusted_top_sites WHERE domain = %s", (domain,)).fetchone()
        top_n = c.execute("SELECT value FROM public.detection_settings WHERE key = 'whitelist_top_n'").fetchone()
        entries = c.execute("SELECT list_type::text AS list_type, is_active FROM public.detection_lists "
                            "WHERE value = %s AND list_type::text = ANY(%s)", (domain, list(TYPES))).fetchall()
    try:
        top_n = int(top_n["value"]) if top_n else 10000
    except (TypeError, ValueError):
        top_n = 10000
    active = sorted({e["list_type"] for e in entries if e["is_active"]})
    inactive = sorted({e["list_type"] for e in entries if not e["is_active"]})
    rank = int(rank["rank"]) if rank else None
    in_tranco = rank is not None and rank <= top_n
    return {"domain": domain, "tranco_rank": rank, "tranco_top_n": top_n, "in_tranco_whitelist": in_tranco,
            "active_in": active, "switched_off_in": inactive,
            "trusted_by_tranco": in_tranco and "not_trusted" not in active,
            "blacklisted": "blacklist" in active}
