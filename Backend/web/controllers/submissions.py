"""Threat URL submissions: an employer reports a URL, an administrator approves it (published to the Global Threat List)
or rejects it. This is the "Threat URL Submissions" tab of URL Approval and the "My Submissions" tab of the Threat URL List.

POST /api/staff/threat-submissions               employer: {"url", "category", "score", "notes"}
GET  /api/staff/threat-submissions/mine          employer: own submissions (?page= &per_page=)
GET  /api/staff/threat-submissions               admin: all submissions (?status= &search= &page= &per_page=) + counts
POST /api/staff/threat-submissions/<id>/review   admin: {"decision": "approve" | "reject", "note": "..."}
"""
from __future__ import annotations

import math

from flask import Blueprint, g, jsonify, request

from aidev.core.features import get_host, normalize
from web.controllers.common import body, err, int_arg, s
from web import detector_sync
from web.db_models import audit, scans, submissions
from web.extensions import limiter
from web.guards import auth_required, role_required

bp = Blueprint("submissions", __name__, url_prefix="/api/staff")

CATEGORIES = ("phishing", "malware", "suspicious", "spam", "scam")
STATUSES = ("pending", "approved", "rejected")


def _score(value):
    """A risk score from 0 to 100 (a number or a numeric string), or None when it is not valid."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return round(n, 2) if math.isfinite(n) and 0 <= n <= 100 else None


def _json(r, admin: bool = False) -> dict:
    out = {
        "id": str(r["id"]), "url": r["url"], "domain": r["domain"], "category": r["category"],
        "risk_score": float(r["risk_score"]), "notes": r["notes"], "status": r["review_status"],
        "review_note": r["review_note"], "created_at": r["created_at"].isoformat(),
        "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
    }
    if admin:
        out["submitted_by"] = r["submitted_by_name"] or r["submitted_by_email"]
        out["submitted_by_email"] = r["submitted_by_email"]
        out["reviewed_by_name"] = r["reviewed_by_name"]
    return out


@bp.post("/threat-submissions")
@limiter.limit("30 per hour")
@auth_required("staff")
@role_required("employer")
def create_submission():
    data = body()
    url, category, notes = s(data, "url", 2048), s(data, "category", 20).lower(), s(data, "notes", 1000)
    score = _score(data.get("score"))
    fields: dict[str, str] = {}
    host = canon = ""
    if not url or any(ord(ch) < 32 for ch in url):
        fields["url"] = "Threat URL is required."
    else:
        try:
            normalized = normalize(url)
            host = get_host(normalized)
            canon = scans.canonical_url(normalized) if host else ""      # no query string, fragment or user info
        except ValueError:
            host = canon = ""
        if not host or len(host) > 253:
            fields["url"] = "Enter a valid URL."
    if category not in CATEGORIES:
        fields["category"] = "Choose a threat category."
    if score is None:
        fields["score"] = "Enter a risk score between 0 and 100."
    if len(notes) < 3:
        fields["notes"] = "Notes / reason is required."
    if fields:
        return err("validation", "Please check the highlighted fields.", 400, fields)

    outcome, row = submissions.create(g.user["id"], url, canon, host, category, score, notes)
    if outcome == "listed":
        return err("conflict", "This URL is already on the Global Threat List.", 409, {"url": "Already on the list."})
    if outcome == "pending":
        return err("conflict", "This URL has already been submitted and is waiting for review.", 409,
                   {"url": "Already waiting for review."})
    audit.log("threat_submission_create", "threat_list", g.user["id"], {"domain": host, "category": category})
    return jsonify({"submission": _json(row)}), 201


@bp.get("/threat-submissions/mine")
@auth_required("staff")
@role_required("employer")
def my_submissions():
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total, counts = submissions.list_mine(g.user["id"], per_page, (page - 1) * per_page)
    return jsonify({"submissions": [_json(r) for r in rows], "total": total, "page": page, "per_page": per_page,
                    "counts": counts})


@bp.get("/threat-submissions")
@auth_required("staff")
@role_required("admin")
def list_submissions():
    status = request.args.get("status", "").lower()
    q = request.args.get("search", "").strip()[:100]
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total, counts = submissions.list_page(status if status in STATUSES else "", q, per_page, (page - 1) * per_page)
    return jsonify({"submissions": [_json(r, admin=True) for r in rows], "total": total, "page": page,
                    "per_page": per_page, "counts": counts})


@bp.post("/threat-submissions/<uuid:sub_id>/review")
@limiter.limit("120 per hour")
@auth_required("staff")
@role_required("admin")
def review_submission(sub_id):
    data = body()
    decision = s(data, "decision", 10)
    if decision not in ("approve", "reject"):
        return err("validation", "Choose approve or reject.", 400)
    note = s(data, "note", 1000)
    outcome = submissions.review(sub_id, g.user["id"], decision, note)
    if outcome == "not_found":
        return err("not_found", "Submission not found.", 404)
    if outcome == "conflict":
        return err("conflict", "This submission has already been reviewed.", 409)
    audit.log(f"threat_submission_{decision}", "threat_list", g.user["id"], {"submission_id": str(sub_id)})
    detector_sync.refresh_threats()                 # an approved submission is blocked by the detector at once
    return jsonify({"submission": _json(submissions.get(sub_id), admin=True)})
