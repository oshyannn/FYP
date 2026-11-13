"""Numbers for the dashboards. A user's numbers come only from their own history; the staff numbers are
system-wide totals and never include anybody's individual scans."""
from __future__ import annotations

from web.db_models.activity import STAFF_ACTIONS
from web import db

# The modules whose actions show on a dashboard's recent-activity list (never logins).
DASHBOARD_MODULES = ("employer_verification", "threat_list", "feedback", "user_management")


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



# The same actions the Activity Logs page shows, so the dashboard and the page always agree.
_ACTION_SQL = "(a.action::text = ANY(%s) OR left(a.action::text, 9) = 'feedback_')"


def recent_activity(limit: int = 5):
    """The latest staff actions of everyone (same list as the Activity Logs page)."""
    with db.transaction() as c:
        return c.execute(
            "SELECT a.action::text AS action, a.module::text AS module, a.created_at, u.full_name AS actor "
            "FROM public.activity_logs a LEFT JOIN public.users u ON u.id = a.user_id "
            f"WHERE {_ACTION_SQL} ORDER BY a.created_at DESC LIMIT %s",
            (list(STAFF_ACTIONS), limit)).fetchall()


def my_recent_activity(user_id, limit: int = 5):
    """The latest staff actions of one person themselves (same list as the Activity Logs page)."""
    with db.transaction() as c:
        return c.execute(
            "SELECT a.action::text AS action, a.module::text AS module, a.created_at "
            "FROM public.activity_logs a "
            f"WHERE a.user_id = %s AND {_ACTION_SQL} ORDER BY a.created_at DESC LIMIT %s",
            (user_id, list(STAFF_ACTIONS), limit)).fetchall()