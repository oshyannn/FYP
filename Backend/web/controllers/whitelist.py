"""Trusted sites (the Trusted Sites screen) and the requests that employers / admins review.

GET    /api/whitelist                              user: own trusted list + own pending requests | admin: the global list
POST   /api/whitelist                              user: asks for an address to be trusted (needs approval) | admin: adds it
DELETE /api/whitelist/<id>                         user: removes from own list | admin: removes from the global list
GET    /api/staff/whitelist-requests               employer / admin: requests (?status= &search= &page= &per_page=) + counts
POST   /api/staff/whitelist-requests/<id>/review   employer / admin: {"decision": "approve" | "reject", "note": "..."}

An address can be a whole website ("example.com") or one page ("example.com/shop"). Before a request is saved it is
checked against every list the detector uses (see db_models/whitelist.py check_request). Duplicates and addresses that
are already covered are rejected with HTTP 409 and a message the screen shows under the input.

A trusted address is shown as SAFE in a scan unless the detector found it malicious (see controllers/scans.py).
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

from flask import Blueprint, g, jsonify, request

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
MAX_PATH = 500


def parse_site(raw: str) -> tuple[str, str, str]:
    """(host, path, error). Accepts a domain, a full address or a page address.
    The host is lower case and IDNA-encoded. The path is lower case, without a trailing slash, and the query string
    and fragment are dropped (they never change which page is meant)."""
    raw = (raw or "").strip()
    if not raw:
        return "", "", "Enter a website address or domain."
    if len(raw) > 2048 or any(ord(ch) < 32 for ch in raw):
        return "", "", "Enter a valid website address."
    try:
        parts = urlsplit(raw if "://" in raw else "https://" + raw)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower().rstrip(".")
        raw_path = parts.path or ""
        parts.port                                     # raises ValueError for a broken port
    except ValueError:
        return "", "", "Enter a valid website address."
    if scheme not in ("http", "https"):
        return "", "", "Only http and https addresses can be trusted."
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        host = ""
    if not host or len(host) > 253 or not _HOST.match(host):
        return "", "", "Enter a valid domain name, for example example.com."

    segs = [seg for seg in raw_path.split("/") if seg]
    if any(seg in (".", "..") for seg in segs):
        return "", "", "Enter a valid page address."
    path = ("/" + "/".join(segs)).lower() if segs else ""
    if len(path) > MAX_PATH:
        return "", "", "This page address is too long."
    return host, path, ""


def parse_domain(raw: str) -> tuple[str, str]:
    """Kept for other controllers that only need the host: (host, error)."""
    host, _path, problem = parse_site(raw)
    return host, problem


def _display(domain: str, path_prefix: str | None) -> str:
    return f"{domain}{path_prefix or ''}"


def _entry_json(r) -> dict:
    mine = r["added_by"] is not None and str(r["added_by"]) == str(g.user["id"])
    return {"id": str(r["id"]), "domain": _display(r["domain"], r["path_prefix"]), "path": r["path_prefix"] or "",
            "scope": r["scope"], "added_at": r["created_at"].isoformat(),
            "added_by": "You" if mine else (r["added_by_name"] or r["added_by_email"] or "—")}


def _request_json(r, staff: bool = False) -> dict:
    out = {
        "id": str(r["id"]), "domain": _display(r["domain"], r["path_prefix"]), "path": r["path_prefix"] or "",
        "reason": r["reason"],
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


def _assess(host: str, path: str) -> tuple[str, float | None]:
    """The detector's opinion of the address, shown to the reviewer. A detector problem must not block the request."""
    try:
        res = analyze(f"https://{host}{path or '/'}")
        level = str(res.get("status", "")).lower()
        level = level if level in LEVELS else "unknown"
        score = min(100.0, max(0.0, float(res.get("risk_score") or 0)))
        return level, (None if level == "unknown" else round(score, 2))
    except Exception:
        log.exception("analyze() failed for a trusted-site request")
        return "unknown", None


# ---- the Trusted Sites screen (users and administrators) --------------------------------------------------------

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
    host, path, problem = parse_site(s(data, "url", 2048) or s(data, "domain", 2048))
    if problem:
        return err("validation", problem, 400, {"url": problem})

    # Duplicate and overlap check against every list the detector uses.
    verdict = whitelist.check_request(g.user["id"], host, path)
    if verdict["conflict"]:
        return err("conflict", verdict["conflict"], 409, {"url": verdict["conflict"]})

    if g.user["role"] == "admin":                                  # an administrator adds to the global list directly
        row = whitelist.add_global(g.user["id"], host, path)
        if row is None:
            msg = "This address is already in the global trusted list."
            return err("conflict", msg, 409, {"url": msg})
        audit.log("whitelist_add", "whitelist", g.user["id"], {"domain": host, "path": path, "scope": "global"})
        return jsonify({"entry": {"id": str(row["id"]), "domain": _display(host, path), "path": path, "scope": "global",
                                  "added_at": row["created_at"].isoformat(), "added_by": "You"},
                        "warnings": verdict["warnings"]}), 201

    reason = s(data, "reason", 500) or None
    level, score = _assess(host, path)
    row = whitelist.create_request(g.user["id"], host, path, reason, score, level)
    if row is None:                                                # lost a race with a second click
        msg = "You already asked for this address. It is waiting for review."
        return err("conflict", msg, 409, {"url": msg})
    audit.log("whitelist_request", "whitelist", g.user["id"], {"domain": host, "path": path, "risk_level": level})
    return jsonify({"request": _request_json(row), "warnings": verdict["warnings"]}), 201


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


# ---- URL Approval: trusted-site requests (employers and administrators) -----------------------------------------

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
    if g.user["role"] == "employer" and len(note) < 3:
        return err("validation", "A reason is required for employers.", 400,
                   {"note": "Enter a reason (at least 3 characters)."})
    outcome = whitelist.review_request(req_id, g.user["id"], decision, note)
    if outcome == "not_found":
        return err("not_found", "Request not found.", 404)
    if outcome == "conflict":
        return err("conflict", "This request has already been reviewed.", 409)
    audit.log(f"whitelist_request_{decision}", "whitelist", g.user["id"],
              {"request_id": str(req_id), **({"reason": note} if note else {})})
    return jsonify({"request": _request_json(whitelist.get_request(req_id), staff=True)})


@bp.patch("/staff/whitelist-requests/<uuid:req_id>")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def update_whitelist_request(req_id):
    data = body()
    host, path, problem = parse_site(s(data, "url", 2048) or s(data, "domain", 2048))
    if problem:
        return err("validation", problem, 400, {"url": problem})
    reason = s(data, "reason", 500)
    if g.user["role"] == "employer" and len(reason) < 3:
        return err("validation", "A reason is required for employers.", 400,
                   {"reason": "Enter a reason (at least 3 characters)."})
    outcome = whitelist.update_approved_request(req_id, host, path)
    if outcome == "not_found":
        return err("not_found", "Request not found.", 404)
    if outcome == "conflict":
        return err("conflict", "Only approved whitelist entries can be modified.", 409)
    if outcome == "duplicate":
        return err("conflict", "This address is already on the global trusted list.", 409, {"url": "Duplicate address."})
    audit.log("whitelist_update", "whitelist", g.user["id"],
              {"request_id": str(req_id), "domain": _display(host, path), **({"reason": reason} if reason else {})})
    return jsonify({"request": _request_json(whitelist.get_request(req_id), staff=True)})


@bp.delete("/staff/whitelist-requests/<uuid:req_id>")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def delete_whitelist_request(req_id):
    data = body()
    reason = s(data, "reason", 500)
    if g.user["role"] == "employer" and len(reason) < 3:
        return err("validation", "A reason is required for employers.", 400,
                   {"reason": "Enter a reason (at least 3 characters)."})
    req = whitelist.get_request(req_id)
    outcome = whitelist.delete_approved_request(req_id)
    if outcome == "not_found":
        return err("not_found", "Request not found.", 404)
    if outcome == "conflict":
        return err("conflict", "Only approved whitelist entries can be deleted.", 409)
    audit.log("whitelist_remove", "whitelist", g.user["id"],
              {"request_id": str(req_id), "domain": _display(req["domain"], req["path_prefix"]) if req else "",
               **({"reason": reason} if reason else {})})
    return jsonify({"deleted": 1})
