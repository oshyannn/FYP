"""Dashboards.

GET /api/dashboard       user (desktop) or paired extension: own scan statistics + the 5 latest scans
GET /api/staff/summary   employer / admin: system-wide counts, scan distribution, items waiting for review
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify

from web.controllers.scans import _scan_json
from web.guards import auth_required, role_required
from web.db_models import scans, stats, threats

bp = Blueprint("dashboard", __name__, url_prefix="/api")


@bp.get("/dashboard")
@auth_required("user", "extension")
def my_dashboard():
    rows, _ = scans.list_page(g.user["id"], "", "", "", 5, 0)
    return jsonify({"stats": stats.user_stats(g.user["id"]), "recent": [_scan_json(r) for r in rows]})


@bp.get("/staff/summary")
@auth_required("staff")
@role_required("employer", "admin")
def staff_summary():
    sysstats = stats.system_stats()
    threat = threats.stats()
    waiting, _ = threats.list_page("pending_review", "", "", 5, 0)
    out = {
        "role": g.user["role"],
        "stats": {
            "total_scans": sysstats["total_scans"],
            "active_threats": threat["total"],
            "pending_threats": threat["pending"],
            "open_feedback": sysstats["open_feedback"],
        },
        "distribution": {k: sysstats[k] for k in ("safe", "suspicious", "malicious", "unknown")},
        "waiting": [{"id": str(r["id"]), "url": r["url"], "risk_level": r["risk_level"], "risk_score": float(r["risk_score"]),
                     "threat_type": r["threat_type"], "last_verified_at": r["last_verified_at"].isoformat()} for r in waiting],
        "activity": None,
    }
    if g.user["role"] == "admin":
        out["stats"].update(total_users=sysstats["total_users"], total_employers=sysstats["total_employers"],
                            pending_employers=sysstats["pending_employers"])
        out["activity"] = [{"action": r["action"], "module": r["module"], "actor": r["actor"],
                            "created_at": r["created_at"].isoformat()} for r in stats.recent_activity(5)]
    return jsonify(out)
