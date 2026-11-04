"""Activity Logs: the audit trail of what staff did.

GET /api/staff/activity-logs     ?actor=admin|employer &search= &page= &per_page=   newest first

administrator: everything admins and employers did; can filter by who (admin / employer) and search a name or email.
employer:      only their OWN actions. The filters are ignored; the person is taken from the login, never from the
               request, so an employer cannot read another employer's or any administrator's trail.
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from web.controllers.common import int_arg
from web.db_models import activity
from web.guards import auth_required, role_required

bp = Blueprint("activity", __name__, url_prefix="/api/staff")


@bp.get("/activity-logs")
@auth_required("staff")
@role_required("employer", "admin")
def list_logs():
    per_page, page = int_arg("per_page", 20, 1, 50), int_arg("page", 1, 1, 100000)
    offset = (page - 1) * per_page
    if g.user["role"] == "admin":
        actor = request.args.get("actor", "").lower()
        q = request.args.get("search", "").strip()[:100]
        rows, total = activity.list_events_all(actor if actor in ("admin", "employer") else "", q, per_page, offset)
        scope = "all"
    else:
        rows, total = activity.list_events_own(g.user["id"], per_page, offset)
        scope = "own"
    targets = activity.targets(rows)
    return jsonify({
        "scope": scope,
        "logs": [{
            "actor": r["actor_name"] or r["actor_email"], "actor_role": r["actor_role"], "action": r["action"],
            "module": r["module"], "target": t, "created_at": r["created_at"].isoformat(),
            "status": "successful",                       # events are written after the action went through
        } for r, t in zip(rows, targets)],
        "total": total, "page": page, "per_page": per_page,
    })
