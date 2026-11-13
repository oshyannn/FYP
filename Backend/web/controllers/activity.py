"""Activity Logs: the audit trail of what staff did.

GET /api/staff/activity-logs
    ?actor=admin|employer   administrator only: who
    &search=                part of a name, an email or the event's details
    &action=  &module=      one of the values listed in db_models/activity.py
    &date_from= &date_to=   YYYY-MM-DD, both days included
    &sort=asc|desc          by time; newest first by default
    &page= &per_page=

administrator: everything admins and employers did; can filter by who.
employer:      only their OWN actions. actor is ignored; the person is taken from the login, never from the request.
"""
from __future__ import annotations

from datetime import date

from flask import Blueprint, g, jsonify, request

from web.controllers.common import err, int_arg
from web.db_models import activity
from web.guards import auth_required, role_required

bp = Blueprint("activity", __name__, url_prefix="/api/staff")


def _day(raw: str):
    """(value, ok). An empty filter is (None, True); text that is not a YYYY-MM-DD day is (None, False)."""
    if not raw:
        return None, True
    try:
        return date.fromisoformat(raw).isoformat(), True
    except ValueError:
        return None, False


@bp.get("/activity-logs")
@auth_required("staff")
@role_required("employer", "admin")
def list_logs():
    per_page, page = int_arg("per_page", 20, 1, 50), int_arg("page", 1, 1, 100000)
    offset = (page - 1) * per_page

    q = request.args.get("search", "").strip()[:100]
    action = request.args.get("action", "").strip()
    module = request.args.get("module", "").strip()
    sort = request.args.get("sort", "desc").strip().lower() or "desc"
    if ((action and action not in activity.ACTION_OPTIONS)
            or (module and module not in activity.MODULE_OPTIONS)
            or sort not in ("asc", "desc")):
        return err("validation", "That filter value is not allowed.", 400)

    date_from, ok_from = _day(request.args.get("date_from", "").strip())
    date_to, ok_to = _day(request.args.get("date_to", "").strip())
    if not (ok_from and ok_to):
        return err("validation", "Use a date like 2026-11-14.", 400)
    if date_from and date_to and date_from > date_to:
        return err("validation", "The start date is after the end date.", 400)

    if g.user["role"] == "admin":
        actor = request.args.get("actor", "").strip().lower()
        if actor and actor not in ("admin", "employer"):
            return err("validation", "That filter value is not allowed.", 400)
        rows, total = activity.list_events_all(actor, q, action, module, date_from, date_to, sort, per_page, offset)
        scope = "all"
    else:
        rows, total = activity.list_events_own(g.user["id"], q, action, module, date_from, date_to, sort,
                                               per_page, offset)
        scope = "own"

    targets = activity.targets(rows)
    return jsonify({
        "scope": scope,
        "logs": [{
            "actor": r["actor_name"] or r["actor_email"], "actor_role": r["actor_role"], "action": r["action"],
            "module": r["module"], "target": t, "created_at": r["created_at"].isoformat(),
        } for r, t in zip(rows, targets)],
        "total": total, "page": page, "per_page": per_page,
    })