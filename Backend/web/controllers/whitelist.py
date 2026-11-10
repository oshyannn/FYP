"""Trusted websites (the Whitelist screen) and the whitelist requests that employers / admins review.

GET    /api/whitelist                              user: the shared list + own older entries + own pending requests | admin: the shared list
POST   /api/whitelist                              user: asks for a website to be trusted (needs approval) | admin: adds it
DELETE /api/whitelist/<id>                         user: removes only own older entry (shared ones can't be) | admin: removes from the shared list
GET    /api/staff/whitelist-requests               employer / admin: requests (?status= &search= &page= &per_page=) + counts
POST   /api/staff/whitelist-requests/<id>/review   employer / admin: {"decision": "approve" | "reject", "note": "..."}

Approving a request puts the website on the SHARED whitelist: it is trusted for every user.
Only staff see who requested / approved an entry; normal users only see the domain and that it is shared.
A trusted website is shown as SAFE in a scan unless the detector found it malicious (see controllers/scans.py).
"""
from __future__ import annotations

import logging
import re

from flask import Blueprint, g, jsonify, request

from aidev.core.features import get_host, normalize
from aidev.detection.detector import analyze
from web.controllers.common import body, err, int_arg, s
from web.db_models import audit, whitelist
from web.extensions import limiter
from web.guards import auth_required, role_required

log = logging.getLogger(__name__)
bp = Blueprint("whitelist", __name__, url_prefix="/api")

STATUSES = ("pending", "approved", "rejected")
LEVELS = ("safe", "suspicious", "malicious", "unknown")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"^(?:{_LABEL}\.)+[a-z][a-z0-9-]{{0,61}}[a-z0-9]$")     # needs a dot; the last part starts with a letter


def parse_domain(raw: str) -> tuple[str, str]:
    """(domain, error). Accepts a bare domain or a full URL and keeps only the host name."""
    if not raw:
        return "", "Enter a website address or domain."
    if len(raw) > 2048 or any(ord(ch) < 32 for ch in raw):
        return "", "Enter a valid website address."
    try:
        host = get_host(normalize(raw))
    except ValueError:
        host = ""
    host = (host or "").strip().lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        host = ""
    if not host or len(host) > 253 or not _HOST.match(host):
        return "", "Enter a valid domain name, for example example.com."
    return host, ""


def _entry_json(r) -> dict:
    mine = r["added_by"] is not None and str(r["added_by"]) == str(g.user["id"])
    out = {"id": str(r["id"]), "domain": r["domain"], "scope": r["scope"], "added_at": r["created_at"].isoformat()}
    if g.user["role"] == "admin":                  # staff: who requested it and who approved / added it
        out["added_by"] = "You" if mine else (r["added_by_name"] or r["added_by_email"] or "—")
        out["requested_by"] = r["requested_by_name"] or r["requested_by_email"]
    elif r["scope"] == "global":                   # normal users: never a name or an email of anybody else
        out["added_by"] = "SafeBrowse (shared)"
    else:
        out["added_by"] = "You"
    return out


def _request_json(r, staff: bool = False) -> dict:
    out = {
        "id": str(r["id"]), "domain": r["domain"], "reason": r["reason"],
        "risk_score": float(r["risk_score"]) if r["risk_score"] is not None else None,
        "risk_level": r["risk_level"], "status": r["status"], "review_note": r["review_note"],
        "created_at": r["created_at"].isoformat(),
        "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
    }
    if staff:
        out["requester"] = r["requester_name"] or r["requester_email"]
        out["requester_email"] = r["requester_email"]
        out["reviewed_by_name"] = r["reviewed_by_name"]
    return out


def _assess(host: str) -> tuple[str, float | None]:
    """The detector's opinion of the domain, shown to the reviewer. A detector problem must not block the request."""
    try:
        res = analyze(f"https://{host}/")
        level = str(res.get("status", "")).lower()
        level = level if level in LEVELS else "unknown"
        score = min(100.0, max(0.0, float(res.get("risk_score") or 0)))
        return level, (None if level == "unknown" else round(score, 2))
    except Exception:
        log.exception("analyze() failed for a whitelist request")
        return "unknown", None


# ---- the Whitelist screen (users and administrators) -------------------------------------------------------------

@bp.get("/whitelist")
@auth_required("user", "staff")
@role_required("user", "admin")
def list_whitelist():
    admin = g.user["role"] == "admin"
    per_page, page = int_arg("per_page", 50, 1, 100), int_arg("page", 1, 1, 100000)
    rows, total = whitelist.list_entries("global" if admin else "user", g.user["id"], per_page, (page - 1) * per_page)
    out = {"scope": "global" if admin else "user", "entries": [_entry_json(r) for r in rows], "total": total,
           "page": page, "per_page": per_page, "requests": []}
    if not admin:
        out["requests"] = [_request_json(r) for r in whitelist.my_requests(g.user["id"])]
    return jsonify(out)


@bp.post("/whitelist")
@limiter.limit("30 per hour")
@auth_required("user", "staff")
@role_required("user", "admin")
def add_whitelist():
    data = body()
    domain, problem = parse_domain(s(data, "url", 2048) or s(data, "domain", 2048))
    if problem:
        return err("validation", problem, 400, {"domain": problem})

    if g.user["role"] == "admin":                                  # an administrator adds to the global list directly
        row = whitelist.add_global(g.user["id"], domain)
        if row is None:
            return err("conflict", "This website is already in the whitelist.", 409, {"domain": "Already trusted."})
        audit.log("whitelist_add", "whitelist", g.user["id"], {"domain": domain, "scope": "global"})
        return jsonify({"entry": {"id": str(row["id"]), "domain": domain, "scope": "global",
                                  "added_at": row["created_at"].isoformat(), "added_by": "You"}}), 201

    if whitelist.trusted_scope(g.user["id"], domain):              # a user asks; an employer / admin decides
        return err("conflict", "This website is already trusted.", 409, {"domain": "Already trusted."})
    reason = s(data, "reason", 500) or None
    level, score = _assess(domain)
    row = whitelist.create_request(g.user["id"], domain, reason, score, level)
    if row is None:
        return err("conflict", "You already asked for this website. It is waiting for review.", 409,
                   {"domain": "Already waiting for review."})
    audit.log("whitelist_request", "whitelist", g.user["id"], {"domain": domain, "risk_level": level})
    return jsonify({"request": _request_json(row)}), 201


@bp.delete("/whitelist/<uuid:entry_id>")
@limiter.limit("60 per hour")
@auth_required("user", "staff")
@role_required("user", "admin")
def remove_whitelist(entry_id):
    scope = "global" if g.user["role"] == "admin" else "user"
    if not whitelist.remove(entry_id, scope, g.user["id"]):        # also what somebody else's entry looks like: no leak
        return err("not_found", "Entry not found.", 404)
    audit.log("whitelist_remove", "whitelist", g.user["id"], {"entry_id": str(entry_id), "scope": scope})
    return jsonify({"deleted": 1})


# ---- URL Approval: whitelist requests (employers and administrators) ---------------------------------------------

@bp.get("/staff/whitelist-requests")
@auth_required("staff")
@role_required("employer", "admin")
def list_requests():
    status = request.args.get("status", "").lower()
    q = request.args.get("search", "").strip()[:100]
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total, counts = whitelist.list_requests(status if status in STATUSES else "", q, per_page, (page - 1) * per_page)
    return jsonify({"requests": [_request_json(r, staff=True) for r in rows], "total": total, "page": page,
                    "per_page": per_page, "counts": counts})


@bp.post("/staff/whitelist-requests/<uuid:req_id>/review")
@limiter.limit("120 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def review_request(req_id):
    data = body()
    decision = s(data, "decision", 10)
    if decision not in ("approve", "reject"):
        return err("validation", "Choose approve or reject.", 400)
    note = s(data, "note", 1000)
    outcome = whitelist.review_request(req_id, g.user["id"], decision, note)
    if outcome == "not_found":
        return err("not_found", "Request not found.", 404)
    if outcome == "conflict":
        return err("conflict", "This request has already been reviewed.", 409)
    row = whitelist.get_request(req_id)
    details = {"request_id": str(req_id), "domain": row["domain"]}
    if decision == "approve":
        details["scope"] = "global"                # recorded because an approval now affects every user
    audit.log(f"whitelist_request_{decision}", "whitelist", g.user["id"], details)
    return jsonify({"request": _request_json(row, staff=True)})
