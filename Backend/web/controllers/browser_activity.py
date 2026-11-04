"""Browser Activity for the desktop app: the pages the paired Chrome extension checked, and whether it is connected.

GET /api/activity   (?status=safe|suspicious|malicious|unknown  &limit=1..100)
    -> {"activity": [scan, ...], "extension": {"paired": n, "connected": bool, "last_seen_at": iso | null}}

The extension saves every page check to the account (POST /api/scans), so there is nothing new to store: this only
reads those records. "connected" = an extension is paired and called the server in the last 10 minutes.
Opening one record in full uses the existing GET /api/scans/<id>.
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from web.controllers.common import int_arg
from web.db_models import browser_activity
from web.extensions import limiter
from web.guards import auth_required

bp = Blueprint("browser_activity", __name__, url_prefix="/api")
LEVELS = ("safe", "suspicious", "malicious", "unknown")
CONNECTED_WITHIN_SECONDS = 600


def _json(r) -> dict:
    return {
        "id": str(r["id"]), "url": r["url"], "domain": r["domain"], "scan_type": r["scan_type"],
        "user_action": r["user_action"], "scanned_at": r["scanned_at"].isoformat(),
        "risk_level": r["risk_level"], "risk_score": float(r["risk_score"]),
    }


@bp.get("/activity")
@limiter.limit("120 per minute")
@auth_required("user")
def activity():
    level = request.args.get("status", "").lower()
    rows = browser_activity.recent(g.user["id"], level if level in LEVELS else "", int_arg("limit", 30, 1, 100))
    st = browser_activity.extension_state(g.user["id"])
    paired = int(st["paired"] or 0)
    ago = float(st["seconds_ago"]) if st["seconds_ago"] is not None else None
    return jsonify({
        "activity": [_json(r) for r in rows],
        "extension": {"paired": paired, "connected": paired > 0 and ago is not None and ago <= CONNECTED_WITHIN_SECONDS,
                      "last_seen_at": st["last_seen"].isoformat() if st["last_seen"] else None},
    })
