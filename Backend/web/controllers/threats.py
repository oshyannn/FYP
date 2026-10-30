"""The global threat URL list (FR 3.4.7).

GET  /api/threats                       everyone signed in: the approved list (staff may also see pending / removed)
POST /api/staff/threats/<id>/review     employer / admin: {"decision": "approve" | "remove"}
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from web.controllers.common import body, err, int_arg, s
from web.extensions import limiter
from web.guards import auth_required, role_required
from web.db_models import audit, threats

bp = Blueprint("threats", __name__, url_prefix="/api")
THREAT_TYPES = ("phishing", "malware", "spam", "scam", "defacement", "unwanted_software", "unknown")
STATUSES = ("active", "pending_review", "revoked")


def _json(r) -> dict:
    return {
        "id": str(r["id"]), "url": r["url"], "domain": r["domain"], "risk_level": r["risk_level"],
        "risk_score": float(r["risk_score"]), "threat_type": r["threat_type"], "status": r["status"],
        "detection_count": r["detection_count"], "created_at": r["created_at"].isoformat(),
        "last_verified_at": r["last_verified_at"].isoformat(),
    }


@bp.get("/threats")
@auth_required("user", "staff")
def list_threats():
    staff = g.user["portal"] == "staff"
    wanted = request.args.get("status", "active").lower()
    # Normal users only ever see approved entries, whatever they ask for.
    status = (wanted if wanted in STATUSES or wanted == "" else "active") if staff else "active"
    q = request.args.get("search", "").strip()[:200]
    ttype = request.args.get("type", "").lower()
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total = threats.list_page(status, q, ttype if ttype in THREAT_TYPES else "", per_page, (page - 1) * per_page)
    stats = threats.stats()
    if not staff:
        stats.pop("pending")                        # the review queue is for staff only
    return jsonify({"threats": [_json(r) for r in rows], "total": total, "page": page, "per_page": per_page,
                    "stats": stats})


@bp.post("/staff/threats/<uuid:gid>/review")
@limiter.limit("120 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def review_threat(gid):
    decision = s(body(), "decision", 10)
    if decision not in ("approve", "remove"):
        return err("validation", "Choose approve or remove.", 400)
    outcome = threats.review(gid, decision, g.user["role"] == "admin")
    if outcome == "not_found":
        return err("not_found", "Threat URL not found.", 404)
    if outcome == "forbidden":
        return err("forbidden", "Only an administrator can do this.", 403)
    if outcome == "conflict":
        return err("conflict", "This entry is already in that state.", 409)
    audit.log(f"threat_{decision}", "threat_list", g.user["id"], {"global_url_id": str(gid)})
    return jsonify({"threat": _json(threats.get(gid))})
