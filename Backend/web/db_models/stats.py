"""Numbers for the dashboards. A user's numbers come only from their own history; the staff numbers are
system-wide totals and never include anybody's individual scans."""
from __future__ import annotations

from web import db


def user_stats(user_id) -> dict:
    row = db.one("""SELECT count(*) AS total,
                           count(*) FILTER (WHERE risk_level = 'safe') AS safe,
                           count(*) FILTER (WHERE risk_level = 'suspicious') AS suspicious,
                           count(*) FILTER (WHERE risk_level = 'malicious') AS malicious,
                           count(*) FILTER (WHERE risk_level = 'unknown') AS unknown
                    FROM public.detection_history WHERE user_id = %s AND is_deleted = false""", (user_id,))
    return {k: int(v) for k, v in row.items()}


def system_stats() -> dict:
    row = db.one("""SELECT
        (SELECT count(*) FROM public.users WHERE role = 'user' AND status = 'active') AS total_users,
        (SELECT count(*) FROM public.users WHERE role = 'employer' AND status = 'active') AS total_employers,
        (SELECT count(*) FROM public.employer_verifications WHERE verification_status = 'pending') AS pending_employers,
        (SELECT count(*) FROM public.feedback WHERE parent_id IS NULL AND status IN ('open', 'in_progress')) AS open_feedback,
        count(*) AS total_scans,
        count(*) FILTER (WHERE risk_level = 'safe') AS safe,
        count(*) FILTER (WHERE risk_level = 'suspicious') AS suspicious,
        count(*) FILTER (WHERE risk_level = 'malicious') AS malicious,
        count(*) FILTER (WHERE risk_level = 'unknown') AS unknown
        FROM public.detection_history""")
    return {k: int(v) for k, v in row.items()}


def recent_activity(limit: int = 5):
    """The latest review / moderation actions (never logins)."""
    with db.transaction() as c:
        return c.execute(
            "SELECT a.action, a.module, a.created_at, u.full_name AS actor FROM public.activity_logs a "
            "LEFT JOIN public.users u ON u.id = a.user_id "
            "WHERE a.module IN ('employer_verification', 'threat_list', 'feedback') "
            "ORDER BY a.created_at DESC LIMIT %s", (limit,)).fetchall()
