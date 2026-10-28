"""Feedback (FR 3.4.5).

Users    POST   /api/feedback                   submit (optionally attach one of their own scan results)
         GET    /api/feedback                   their feedback with its status (?status= &search= &page=)
         GET    /api/feedback/<id>              one thread: message, attached scan, replies
         PATCH  /api/feedback/<id>              modify (only while open / in progress)
         POST   /api/feedback/<id>/replies      follow-up message
Staff    GET    /api/staff/feedback             every thread (?status= &category= &search= &page=) + counts
         GET    /api/staff/feedback/<id>        one thread with the author
         POST   /api/staff/feedback/<id>/replies  reply (not allowed on a closed thread)
         POST   /api/staff/feedback/<id>/status   in_progress | resolved | closed
"""
from __future__ import annotations

import uuid

from flask import Blueprint, g, jsonify, request

from web.db_models import audit, feedback
from web.extensions import limiter
from web.guards import auth_required, role_required


# Small request helpers kept here so this module depends on nothing but guards / extensions / db_models.
def err(code: str, message: str, status: int, fields: dict | None = None):
    payload = {"error": {"code": code, "message": message}}
    if fields:
        payload["error"]["fields"] = fields
    return jsonify(payload), status


def body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def s(data: dict, key: str, maxlen: int = 256) -> str:
    """A trimmed string field, or '' if missing / not a string."""
    v = data.get(key)
    return v.strip()[:maxlen] if isinstance(v, str) else ""


def int_arg(name: str, default: int, lo: int, hi: int) -> int:
    """A clamped integer from the query string (bad input falls back to the default)."""
    try:
        return min(hi, max(lo, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


bp = Blueprint("feedback", __name__, url_prefix="/api")
CATEGORIES = ("false_positive", "false_negative", "bug_report", "suggestion", "other")
STATUSES = ("open", "in_progress", "resolved", "closed")
STAFF_STATUSES = ("in_progress", "resolved", "closed")
OWN = auth_required("user")
STAFF = (auth_required("staff"), role_required("employer", "admin"))


def _row(r) -> dict:
    return {
        "id": str(r["id"]), "category": r["category"], "subject": r["subject"], "status": r["status"],
        "created_at": r["created_at"].isoformat(), "updated_at": r["updated_at"].isoformat(),
        "has_scan": bool(r["has_scan"]), "reply_count": int(r["reply_count"]),
        "last_reply_at": r["last_reply_at"].isoformat() if r["last_reply_at"] else None,
        "author_name": r["author_name"], "author_email": r["author_email"],
    }


def _thread(t, replies, *, staff: bool) -> dict:
    out = {
        "id": str(t["id"]), "category": t["category"], "subject": t["subject"], "message": t["message"],
        "status": t["status"], "created_at": t["created_at"].isoformat(), "updated_at": t["updated_at"].isoformat(),
        "resolved_at": t["resolved_at"].isoformat() if t["resolved_at"] else None,
        "resolved_by_name": t["resolved_by_name"],
        "can_edit": (not staff) and t["status"] in feedback.EDITABLE,
        "can_reply": t["status"] != "closed",
        "attached_scan": None,
        "replies": [{"id": str(r["id"]), "message": r["message"], "created_at": r["created_at"].isoformat(),
                     "author_name": r["author_name"], "author_role": r["author_role"]} for r in replies],
    }
    if t["scan_id"]:
        out["attached_scan"] = {"id": str(t["scan_id"]), "url": t["scan_url"], "domain": t["scan_domain"],
                                "risk_level": t["scan_level"], "risk_score": float(t["scan_score"]),
                                "scanned_at": t["scan_at"].isoformat(), "analysis": t["scan_analysis"]}
    if staff:
        out["author_name"], out["author_email"] = t["author_name"], t["author_email"]
    return out


def _clean(data: dict, *, partial: bool):
    """Returns (changes, field_errors). When partial, only the keys that were sent are checked."""
    changes, errors = {}, {}
    if not partial or "category" in data:
        cat = s(data, "category", 30)
        if cat in CATEGORIES:
            changes["category"] = cat
        else:
            errors["category"] = "Choose a feedback type."
    if not partial or "subject" in data:
        subject = " ".join(s(data, "subject", 200).split())
        if len(subject) < 3:
            errors["subject"] = "Enter a subject (at least 3 characters)."
        else:
            changes["subject"] = subject
    if not partial or "message" in data:
        message = s(data, "message", 4000)
        if len(message) < 10:
            errors["message"] = "Describe your feedback (at least 10 characters)."
        else:
            changes["message"] = message
    if "history_id" in data:
        raw = data["history_id"]
        if raw in (None, ""):
            changes["history_id"] = None
        else:
            try:
                changes["history_id"] = uuid.UUID(str(raw))
            except ValueError:
                errors["history_id"] = "Choose one of your scan results."
    return changes, errors


def _reply_text(data: dict):
    message = s(data, "message", 4000)
    if len(message) < 2:
        return None, err("validation", "Write a message.", 400, {"message": "Write a message."})
    return message, None


# ---------------------------------------------------------------- users
@bp.post("/feedback")
@limiter.limit("20 per hour")
@OWN
def submit():
    changes, errors = _clean(body(), partial=False)
    if errors:
        return err("validation", "Please correct the highlighted fields.", 400, errors)
    fid = feedback.create(g.user["id"], changes["category"], changes["subject"], changes["message"], changes.get("history_id"))
    if fid == "bad_scan":
        return err("validation", "Choose one of your own scan results.", 400, {"history_id": "Choose one of your scan results."})
    audit.log("feedback_submitted", "feedback", g.user["id"], {"feedback_id": str(fid), "category": changes["category"]})
    t, replies = feedback.get_thread(fid, g.user["id"])
    return jsonify({"feedback": _thread(t, replies, staff=False)}), 201


@bp.get("/feedback")
@OWN
def my_feedback():
    status = request.args.get("status", "").lower()
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total, counts = feedback.list_page(owner_id=g.user["id"], status=status if status in STATUSES else "", category="",
                                             q=request.args.get("search", "").strip()[:100], limit=per_page, offset=(page - 1) * per_page)
    return jsonify({"feedback": [_row(r) for r in rows], "total": total, "page": page, "per_page": per_page, "counts": counts})


@bp.get("/feedback/<uuid:fid>")
@OWN
def my_thread(fid):
    t, replies = feedback.get_thread(fid, g.user["id"])
    if not t:                                           # also what somebody else's thread looks like: no leak
        return err("not_found", "Feedback not found.", 404)
    return jsonify({"feedback": _thread(t, replies, staff=False)})


@bp.patch("/feedback/<uuid:fid>")
@limiter.limit("60 per hour")
@OWN
def modify(fid):
    changes, errors = _clean(body(), partial=True)
    if errors:
        return err("validation", "Please correct the highlighted fields.", 400, errors)
    if not changes:
        return err("validation", "Nothing to change.", 400)
    outcome = feedback.update(fid, g.user["id"], changes)
    if outcome == "not_found":
        return err("not_found", "Feedback not found.", 404)
    if outcome == "locked":
        return err("locked", "This feedback can no longer be edited.", 409)
    if outcome == "bad_scan":
        return err("validation", "Choose one of your own scan results.", 400, {"history_id": "Choose one of your scan results."})
    t, replies = feedback.get_thread(fid, g.user["id"])
    return jsonify({"feedback": _thread(t, replies, staff=False)})


@bp.post("/feedback/<uuid:fid>/replies")
@limiter.limit("60 per hour")
@OWN
def user_reply(fid):
    message, bad = _reply_text(body())
    if bad:
        return bad
    outcome = feedback.add_reply(fid, g.user["id"], message, staff=False, owner_id=g.user["id"])
    if outcome == "not_found":
        return err("not_found", "Feedback not found.", 404)
    if outcome == "closed":
        return err("closed", "This feedback is closed.", 409)
    t, replies = feedback.get_thread(fid, g.user["id"])
    return jsonify({"feedback": _thread(t, replies, staff=False)}), 201


# ---------------------------------------------------------------- staff
@bp.get("/staff/feedback")
@STAFF[0]
@STAFF[1]
def staff_list():
    status = request.args.get("status", "").lower()
    category = request.args.get("category", "").lower()
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total, counts = feedback.list_page(owner_id=None, status=status if status in STATUSES else "",
                                             category=category if category in CATEGORIES else "",
                                             q=request.args.get("search", "").strip()[:100], limit=per_page, offset=(page - 1) * per_page)
    return jsonify({"feedback": [_row(r) for r in rows], "total": total, "page": page, "per_page": per_page, "counts": counts})


@bp.get("/staff/feedback/<uuid:fid>")
@STAFF[0]
@STAFF[1]
def staff_thread(fid):
    t, replies = feedback.get_thread(fid)
    if not t:
        return err("not_found", "Feedback not found.", 404)
    return jsonify({"feedback": _thread(t, replies, staff=True)})


@bp.post("/staff/feedback/<uuid:fid>/replies")
@limiter.limit("120 per hour")
@STAFF[0]
@STAFF[1]
def staff_reply(fid):
    data = body()
    message, bad = _reply_text(data)
    if bad:
        return bad
    new_status = s(data, "status", 20)
    if new_status and new_status not in STAFF_STATUSES:
        return err("validation", "Invalid status.", 400, {"status": "Invalid status."})
    outcome = feedback.add_reply(fid, g.user["id"], message, staff=True, new_status=new_status)
    if outcome == "not_found":
        return err("not_found", "Feedback not found.", 404)
    if outcome == "closed":
        return err("closed", "This feedback is closed, so it cannot be replied to.", 409)
    audit.log("feedback_replied", "feedback", g.user["id"], {"feedback_id": str(fid), "status": new_status or None})
    t, replies = feedback.get_thread(fid)
    return jsonify({"feedback": _thread(t, replies, staff=True)}), 201


@bp.post("/staff/feedback/<uuid:fid>/status")
@limiter.limit("120 per hour")
@STAFF[0]
@STAFF[1]
def staff_status(fid):
    status = s(body(), "status", 20)
    if status not in STAFF_STATUSES:
        return err("validation", "Choose in progress, resolved or closed.", 400, {"status": "Invalid status."})
    outcome = feedback.set_status(fid, g.user["id"], status)
    if outcome == "not_found":
        return err("not_found", "Feedback not found.", 404)
    if outcome == "closed":
        return err("closed", "This feedback is already closed and cannot be changed.", 409)
    audit.log(f"feedback_{status}", "feedback", g.user["id"], {"feedback_id": str(fid)})
    t, replies = feedback.get_thread(fid)
    return jsonify({"feedback": _thread(t, replies, staff=True)})
