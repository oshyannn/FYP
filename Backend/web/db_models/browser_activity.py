"""Browser Activity (Model layer): the pages the paired Chrome extension checked for this user, newest first.

The rows are the same records as the Detection History (public.detection_history); this file only reads the ones the
extension created ('auto' and 'redirect'), and works out whether an extension is paired and recently active.
Every query is scoped to the owner.
"""
from __future__ import annotations

from web import db

_COLS = ("h.id, h.url, h.domain, h.scan_type::text AS scan_type, h.user_action::text AS user_action, "
         "h.scanned_at, h.risk_level::text AS risk_level, h.risk_score")


def recent(user_id, level: str, limit: int):
    p = {"uid": user_id, "level": level, "limit": limit}
    with db.transaction() as c:
        return c.execute(
            f"SELECT {_COLS} FROM public.detection_history h "
            "WHERE h.user_id = %(uid)s AND h.is_deleted = false AND h.scan_type IN ('auto', 'redirect') "
            "AND (%(level)s = '' OR h.risk_level = NULLIF(%(level)s, '')::public.risk_level) "
            "ORDER BY h.scanned_at DESC LIMIT %(limit)s", p).fetchall()


def extension_state(user_id):
    """paired = number of live extension sessions; seconds_ago = time since the extension last called the server."""
    return db.one(
        "SELECT count(*) AS paired, max(last_seen_at) AS last_seen, "
        "extract(epoch FROM now() - max(last_seen_at)) AS seconds_ago "
        "FROM public.sessions WHERE user_id = %s AND portal = 'extension' AND revoked_at IS NULL "
        "AND expires_at > now()", (user_id,))
