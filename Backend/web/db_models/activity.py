"""The audit trail of staff actions (Model layer), read from public.activity_logs, which web/db_models/audit.py fills.
Logins, password changes and the like are not shown here, only what administrators and employers did in the system.

  list_events_all : administrator view. Admins and employers, optionally one of them.
  list_events_own : employer view. Only the signed-in person's own actions. The caller passes their own id, never one
                    taken from the request.
Both take the same filters: search (name, email or the event's details), action, module, a date range and sort order.
"""
from __future__ import annotations

import logging

from web import db

log = logging.getLogger(__name__)

# What staff can do that belongs in the trail. feedback_<status> events are matched by prefix.
STAFF_ACTIONS = (
    "employer_approved", "employer_rejected",
    "threat_approve", "threat_remove",
    "threat_submission_create", "threat_submission_approve", "threat_submission_reject",
    "whitelist_add", "whitelist_remove", "whitelist_request_approve", "whitelist_request_reject",
    "user_activated", "user_deactivated", "user_updated", "user_deleted", "user_password_reset_sent",
)
_IN = ", ".join(f"'{a}'" for a in STAFF_ACTIONS)
_ACTION = f"(a.action::text IN ({_IN}) OR left(a.action::text, 9) = 'feedback_')"

# The values the screen may filter by. lib/admin.ts must list the same ones.
ACTION_OPTIONS = STAFF_ACTIONS + ("feedback_replied", "feedback_in_progress", "feedback_resolved", "feedback_closed")
MODULE_OPTIONS = ("employer_verification", "threat_list", "whitelist", "user_management", "feedback")
_ORDER = {"asc": "ASC", "desc": "DESC"}     # the only sort directions; the request never writes SQL


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _where(scope_sql: str, scope: dict, q: str, action: str, module: str, date_from, date_to):
    """The WHERE clause. Values go in only as parameters; the SQL text itself is fixed."""
    where = (f"{scope_sql} AND {_ACTION} "
             "AND (%(q)s = '' OR u.full_name ILIKE %(like)s ESCAPE '\\' OR u.email::text ILIKE %(like)s ESCAPE '\\' "
             "OR a.details::text ILIKE %(like)s ESCAPE '\\') "
             "AND (%(action)s = '' OR a.action::text = %(action)s) "
             "AND (%(module)s = '' OR a.module::text = %(module)s) "
             "AND (%(date_from)s::date IS NULL OR a.created_at >= %(date_from)s::date) "
             "AND (%(date_to)s::date IS NULL OR a.created_at < %(date_to)s::date + 1)")
    params = dict(scope, q=q, like=_like(q), action=action, module=module, date_from=date_from, date_to=date_to)
    return where, params


def _page(where: str, params: dict, sort: str, limit: int, offset: int):
    p = dict(params, limit=limit, offset=offset)
    order = _ORDER.get(sort, "DESC")
    with db.transaction() as c:
        total = c.execute("SELECT count(*) AS n FROM public.activity_logs a "
                          f"JOIN public.users u ON u.id = a.user_id WHERE {where}", p).fetchone()["n"]
        rows = c.execute("SELECT a.action::text AS action, a.module::text AS module, a.details, a.created_at, "
                         "u.role::text AS actor_role, u.full_name AS actor_name, u.email::text AS actor_email "
                         f"FROM public.activity_logs a JOIN public.users u ON u.id = a.user_id WHERE {where} "
                         f"ORDER BY a.created_at {order} LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
    return rows, total


def list_events_all(actor: str, q: str, action: str, module: str, date_from, date_to, sort: str,
                    limit: int, offset: int):
    """actor: '' (admins and employers) | 'admin' | 'employer'. date_from / date_to: 'YYYY-MM-DD' or None."""
    scope = "u.role::text IN ('admin', 'employer') AND (%(actor)s = '' OR u.role::text = %(actor)s)"
    where, p = _where(scope, {"actor": actor}, q, action, module, date_from, date_to)
    return _page(where, p, sort, limit, offset)


def list_events_own(user_id, q: str, action: str, module: str, date_from, date_to, sort: str,
                    limit: int, offset: int):
    where, p = _where("a.user_id = %(uid)s", {"uid": user_id}, q, action, module, date_from, date_to)
    return _page(where, p, sort, limit, offset)


def _names(sql: str, ids: set) -> dict:
    """{id: text} for the ids that still exist. A missing table or row just means a plainer label, never an error."""
    if not ids:
        return {}
    try:
        with db.transaction() as c:
            return {str(r["id"]): r["label"] for r in c.execute(sql, (sorted(ids),)).fetchall()}
    except Exception:
        log.exception("activity log: could not look up names")
        return {}


def _detail(r, key: str):
    d = r["details"] if isinstance(r["details"], dict) else {}
    v = d.get(key)
    return v if isinstance(v, str) and v else None


def targets(rows) -> list[str]:
    """A readable 'what was it done to' for every row: the account, domain or URL, looked up from the ids the
    events carry. Falls back to a general word."""
    need = {"verification_id": set(), "global_url_id": set(), "submission_id": set(), "request_id": set()}
    for r in rows:
        for k, bucket in need.items():
            v = _detail(r, k)
            if v:
                bucket.add(v)
    employers = _names("SELECT v.id, u.email::text AS label FROM public.employer_verifications v "
                       "JOIN public.users u ON u.id = v.user_id WHERE v.id = ANY(%s::uuid[])", need["verification_id"])
    urls = _names("SELECT id, url AS label FROM public.global_urls WHERE id = ANY(%s::uuid[])", need["global_url_id"])
    subs = _names("SELECT id, url AS label FROM public.threat_submissions WHERE id = ANY(%s::uuid[])", need["submission_id"])
    reqs = _names("SELECT id, domain AS label FROM public.whitelist_requests WHERE id = ANY(%s::uuid[])", need["request_id"])

    out = []
    for r in rows:
        a = r["action"]
        if a.startswith("employer_"):
            t = employers.get(_detail(r, "verification_id") or "") or "Employer application"
        elif a.startswith("threat_submission_"):
            t = subs.get(_detail(r, "submission_id") or "") or _detail(r, "domain") or "Threat submission"
        elif a.startswith("threat_"):
            t = urls.get(_detail(r, "global_url_id") or "") or "Threat URL"
        elif a.startswith("whitelist_request_"):
            t = reqs.get(_detail(r, "request_id") or "") or "Whitelist request"
        elif a.startswith("whitelist_"):
            t = _detail(r, "domain") or "Whitelist entry"
        elif a.startswith("user_"):
            t = _detail(r, "email") or "User account"
        elif a.startswith("feedback_"):
            t = "User feedback"
        else:
            t = "—"
        out.append(t)
    return out