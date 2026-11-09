"""The lists the detector really uses, visible to every signed-in person (read-only).

GET /api/lists/summary                         how big each list is, and when the big ones were last updated
GET /api/lists/<kind>?search= &page= &per_page=   kind: trusted | blocked | feed | adult | shared
GET /api/lists/check?domain=                   which lists a website is on

The adult list has about a million domains, so it can only be searched (at least 3 letters), not browsed.
Staff change these lists in URL Approval / Whitelist (see controllers/system_lists.py and controllers/threats.py).
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from web.controllers.common import err, int_arg
from web.controllers.whitelist import parse_domain
from web.db_models import lists_view
from web.guards import auth_required

bp = Blueprint("lists_view", __name__, url_prefix="/api/lists")


def _iso(v):
    return v.isoformat() if v else None


@bp.get("/summary")
@auth_required("user", "staff")
def summary():
    return jsonify(lists_view.summary())


@bp.get("/check")
@auth_required("user", "staff")
def check():
    domain, problem = parse_domain(request.args.get("domain", "").strip()[:2048])
    if problem:
        return err("validation", problem, 400, {"domain": problem})
    return jsonify(lists_view.check(domain))


@bp.get("/<kind>")
@auth_required("user", "staff")
def items(kind):
    if kind not in lists_view.KINDS:
        return err("not_found", "Unknown list.", 404)
    q = request.args.get("search", "").strip()[:100]
    if kind == "adult" and len(q) < lists_view.ADULT_MIN_SEARCH:
        return err("validation", f"Type at least {lists_view.ADULT_MIN_SEARCH} letters to search the adult-site list.", 400,
                   {"search": "Too short."})
    per_page, page = int_arg("per_page", 25, 1, 100), int_arg("page", 1, 1, 100000)
    rows, total, capped = lists_view.items(kind, q, per_page, (page - 1) * per_page)
    return jsonify({"kind": kind, "total": total, "capped": capped, "page": page, "per_page": per_page,
                    "items": [{"item": r["item"], "source": r["source"], "detail": r["detail"], "level": r["level"],
                               "score": float(r["score"]) if r["score"] is not None else None,
                               "added_at": _iso(r["added_at"])} for r in rows]})
