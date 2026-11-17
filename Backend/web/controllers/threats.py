"""The global threat URL list (FR 3.4.7).

GET  /api/threats                       everyone signed in: the approved list (staff may also see pending / removed)
POST /api/staff/threats/<id>/review     employer / admin: {"decision": "approve" | "remove", "match_scope": "auto" | "exact" (admin, optional)}
PATCH /api/staff/threats/<id>/scope     admin: {"match_scope": "auto" | "exact"}
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from aidev.core.features import get_host, normalize
from web.controllers.common import body, err, int_arg, s
from web.controllers.whitelist import parse_site
from web.extensions import limiter
from web.guards import auth_required, role_required
from web import detector_sync
from web.db_models import audit, scans, threats

bp = Blueprint("threats", __name__, url_prefix="/api")
THREAT_TYPES = ("phishing", "malware", "spam", "scam", "defacement", "unwanted_software", "unknown")
STATUSES = ("active", "pending_review", "revoked")
LEVELS = ("suspicious", "malicious")
SORTS = ("newest", "oldest", "detections", "url")
SCOPES = ("auto", "exact")      # auto: a front-page entry covers the whole domain (original behaviour); exact: only this address


def _json(r) -> dict:
    return {
        "id": str(r["id"]), "url": r["url"], "domain": r["domain"], "risk_level": r["risk_level"],
        "is_malicious": r["risk_level"] == "malicious",
        "risk_score": float(r["risk_score"]), "threat_type": r["threat_type"], "status": r["status"],
        "detection_count": r["detection_count"], "created_at": r["created_at"].isoformat(),
        "last_verified_at": r["last_verified_at"].isoformat(), "match_scope": r["match_scope"],
        "notes": r.get("notes"),
    }


def _validate_threat_url(raw_url: str):
    """Returns (canon, url_hash, host, error_msg)."""
    if not raw_url or any(ord(ch) < 32 for ch in raw_url):
        return "", "", "", "Enter a valid website URL or domain."
    host, _path, problem = parse_site(raw_url)
    if problem:
        return "", "", "", problem
    try:
        normalized = normalize(raw_url)
        canon = scans.canonical_url(normalized)
    except ValueError:
        return "", "", "", "Enter a valid website URL."
    return canon, scans.url_hash(canon), host, ""


@bp.get("/threats")
@auth_required("user", "staff")
def list_threats():
    staff = g.user["portal"] == "staff"
    wanted = request.args.get("status", "active").lower()
    # Normal users only ever see approved entries, whatever they ask for.
    status = (wanted if wanted in STATUSES or wanted == "" else "active") if staff else "active"
    q = request.args.get("search", "").strip()[:200]
    ttype = request.args.get("type", "").lower()
    level = request.args.get("risk_level", "").lower()
    sort = request.args.get("sort", "newest").lower()
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total = threats.list_page(
        status, q, ttype if ttype in THREAT_TYPES else "", per_page, (page - 1) * per_page,
        risk_level=level if level in LEVELS else "", sort=sort if sort in SORTS else "newest",
    )
    stats = threats.stats()
    if not staff:
        stats.pop("pending", None)                        # the review queue is for staff only
        stats.pop("revoked", None)
    return jsonify({"threats": [_json(r) for r in rows], "total": total, "page": page, "per_page": per_page,
                    "stats": stats})


@bp.post("/staff/threats")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def create_threat():
    """Manually add a threat URL directly to the active Global Threat List (boolean malicious/suspicious)."""
    data = body()
    raw_url = s(data, "url", 2048)
    ttype = s(data, "threat_type", 24).lower() or "phishing"
    scope = s(data, "match_scope", 10).lower() or "auto"
    notes = s(data, "notes", 1000) or s(data, "reason", 1000)
    is_malicious = bool(data.get("is_malicious", True))

    canon, h, host, url_err = _validate_threat_url(raw_url)
    fields: dict[str, str] = {}
    if url_err:
        fields["url"] = url_err
    if ttype not in THREAT_TYPES:
        fields["threat_type"] = "Choose a valid threat type."
    if scope not in SCOPES:
        fields["match_scope"] = "Choose auto or exact."
    if g.user["role"] == "employer" and len(notes) < 3:
        fields["reason"] = "Enter a reason (at least 3 characters)."
    if fields:
        return err("validation", "Please check the highlighted fields.", 400, fields)

    outcome, row = threats.create_manual(g.user["id"], raw_url, canon, h, host, ttype, is_malicious, scope, notes or None)
    if outcome == "duplicate":
        return err("conflict", "This URL is already in the threat list.", 409, {"url": "Duplicate URL: already exists."})
    audit.log("threat_add", "threat_list", g.user["id"],
              {"global_url_id": str(row["id"]), "url": canon, "is_malicious": is_malicious,
               **({"reason": notes} if notes else {})})
    detector_sync.refresh_threats()
    return jsonify({"threat": _json(row)}), 201


@bp.patch("/staff/threats/<uuid:gid>")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def update_threat(gid):
    data = body()
    ttype = s(data, "threat_type", 24).lower() or None
    scope = s(data, "match_scope", 10).lower() or None
    notes = s(data, "notes", 1000) or s(data, "reason", 1000) or None
    has_mal = "is_malicious" in data
    is_malicious = bool(data.get("is_malicious")) if has_mal else None
    raw_url = s(data, "url", 2048)

    fields: dict[str, str] = {}
    canon = h = host = None
    if raw_url:
        canon, h, host, url_err = _validate_threat_url(raw_url)
        if url_err:
            fields["url"] = url_err
    if ttype is not None and ttype not in THREAT_TYPES:
        fields["threat_type"] = "Choose a valid threat type."
    if scope is not None and scope not in SCOPES:
        fields["match_scope"] = "Choose auto or exact."
    if g.user["role"] == "employer" and (not notes or len(notes) < 3):
        fields["reason"] = "Enter a reason (at least 3 characters)."
    if fields:
        return err("validation", "Please check the highlighted fields.", 400, fields)

    outcome = threats.update_entry(gid, ttype, is_malicious, scope, notes, raw_url or None, canon, h, host)
    if outcome == "not_found":
        return err("not_found", "Threat URL not found.", 404)
    if outcome == "duplicate":
        return err("conflict", "Another entry with this URL already exists.", 409, {"url": "Duplicate URL."})
    audit.log("threat_update", "threat_list", g.user["id"],
              {"global_url_id": str(gid), **({"reason": notes} if notes else {})})
    detector_sync.refresh_threats()
    return jsonify({"threat": _json(threats.get(gid))})


@bp.delete("/staff/threats/<uuid:gid>")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def delete_threat(gid):
    data = body()
    reason = s(data, "reason", 500)
    if g.user["role"] == "employer" and len(reason) < 3:
        return err("validation", "A reason is required for employers.", 400,
                   {"reason": "Enter a reason (at least 3 characters)."})
    existing = threats.get(gid)
    if not existing or not threats.delete_entry(gid):
        return err("not_found", "Threat URL not found.", 404)
    audit.log("threat_delete", "threat_list", g.user["id"],
              {"global_url_id": str(gid), "url": existing["url"], **({"reason": reason} if reason else {})})
    detector_sync.refresh_threats()
    return jsonify({"deleted": 1})


@bp.post("/staff/threats/<uuid:gid>/review")
@limiter.limit("120 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def review_threat(gid):
    data = body()
    decision = s(data, "decision", 10)
    if decision not in ("approve", "remove"):
        return err("validation", "Choose approve or remove.", 400)
    scope = s(data, "match_scope", 10) or None
    if scope is not None and scope not in SCOPES:
        return err("validation", "match_scope must be auto or exact.", 400)
    reason = s(data, "reason", 500) or s(data, "note", 500)
    if g.user["role"] == "employer" and len(reason) < 3:
        return err("validation", "A reason is required for employers.", 400,
                   {"reason": "Enter a reason (at least 3 characters)."})
    outcome = threats.review(gid, decision, True, scope)
    if outcome == "not_found":
        return err("not_found", "Threat URL not found.", 404)
    if outcome == "forbidden":
        return err("forbidden", "You are not allowed to do this.", 403)
    if outcome == "conflict":
        return err("conflict", "This entry is already in that state.", 409)
    audit.log(f"threat_{decision}", "threat_list", g.user["id"],
              {"global_url_id": str(gid), **({"reason": reason} if reason else {})})
    detector_sync.refresh_threats()                 # an approval / removal changes what the detector blocks
    return jsonify({"threat": _json(threats.get(gid))})


@bp.patch("/staff/threats/<uuid:gid>/scope")
@limiter.limit("120 per hour")
@auth_required("staff")
@role_required("admin")
def set_scope(gid):
    """Optional: make a front-page entry cover only that exact address (exact) or the whole site (auto, the default)."""
    scope = s(body(), "match_scope", 10)
    if scope not in SCOPES:
        return err("validation", "match_scope must be auto or exact.", 400)
    if not threats.set_scope(gid, scope):
        return err("not_found", "Threat URL not found.", 404)
    audit.log("threat_scope", "threat_list", g.user["id"], {"global_url_id": str(gid), "match_scope": scope})
    detector_sync.refresh_threats()
    return jsonify({"threat": _json(threats.get(gid))})
