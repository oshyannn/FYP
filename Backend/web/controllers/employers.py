"""Employer verification for administrators (FR 3.4.6).

GET  /api/admin/employers                      applications (?status= &search= &page= &per_page=) + counts
POST /api/admin/employers/<id>/review          {"decision": "approve" | "reject", "remarks": "..."}
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from web.controllers.common import body, err, int_arg, s
from web.extensions import limiter
from web.guards import auth_required, role_required
from web.db_models import audit, employers

bp = Blueprint("employers", __name__, url_prefix="/api/admin")
STATUSES = ("pending", "approved", "rejected")


def _json(r) -> dict:
    return {
        "id": str(r["id"]), "name": r["name"], "email": r["email"], "company_name": r["company_name"],
        "company_registration_no": r["company_registration_no"], "status": r["status"], "remarks": r["remarks"],
        "submitted_at": r["submitted_at"].isoformat(),
        "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
        "reviewed_by_name": r["reviewed_by_name"], "role": r["role"], "account_status": r["account_status"],
        "email_verified": bool(r["email_verified"]),
    }


@bp.get("/employers")
@auth_required("staff")
@role_required("admin")
def list_employers():
    status = request.args.get("status", "").lower()
    q = request.args.get("search", "").strip()[:100]
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total, counts = employers.list_page(status if status in STATUSES else "", q, per_page, (page - 1) * per_page)
    return jsonify({"applications": [_json(r) for r in rows], "total": total, "page": page,
                    "per_page": per_page, "counts": counts})


@bp.post("/employers/<uuid:v_id>/review")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("admin")
def review_employer(v_id):
    data = body()
    decision = {"approve": "approved", "reject": "rejected"}.get(s(data, "decision", 10))
    remarks = s(data, "remarks", 1000)
    if not decision:
        return err("validation", "Choose approve or reject.", 400)
    if decision == "rejected" and len(remarks) < 3:
        return err("validation", "Give a reason for rejecting.", 400, {"remarks": "Give a reason for rejecting."})
    outcome = employers.review(v_id, g.user["id"], decision, remarks)
    if outcome == "not_found":
        return err("not_found", "Application not found.", 404)
    if outcome == "forbidden":
        return err("forbidden", "This account cannot be changed here.", 403)
    if outcome == "not_verified":
        return err("not_verified", "The applicant has not verified their email yet.", 409)
    audit.log(f"employer_{decision}", "employer_verification", g.user["id"],
              {"verification_id": str(v_id), "remarks": remarks})
    return jsonify({"application": _json(employers.get(v_id))})
