"""User Management for employers and administrators.

GET    /api/staff/users                     ?search= &role= &status= &tab=accounts|deleted &page= &per_page=
GET    /api/staff/users/<id>                one account (deleted ones too, read-only)
PATCH  /api/staff/users/<id>                {"full_name": "..."}      (the role and email are never changed here)
POST   /api/staff/users/<id>/status         {"status": "active" | "inactive"}
DELETE /api/staff/users/<id>                administrator only
POST   /api/staff/users/<id>/password-reset admin: reset now; employer: asks for approval

Who sees and changes whom is in db_models/user_admin.py (VIEW_ROLES / ACT_ROLES):
  administrator: sees users, employers and administrators, changes users and employers directly. For another
                 administrator's account it can only REQUEST a deactivation, activation or deletion; a third
                 administrator has to approve (see staff_accounts.py).
  employer:      sees and changes users only, and cannot delete.
Nobody can change their own account here. Every account JSON carries "actions": what THIS person may do with it,
so the screen never has to repeat these rules.
"""
from __future__ import annotations

import logging

from flask import Blueprint, g, jsonify, request

import config
from web import mailer
from web.controllers.common import body, err, int_arg, s
from web.db_models import audit, password_reset as pr, sessions, staff_accounts, tokens, user_admin, users
from web.extensions import limiter
from web.guards import auth_required, role_required
from web.security import hash_password, make_temp_password

log = logging.getLogger(__name__)
bp = Blueprint("user_admin", __name__, url_prefix="/api/staff")

ROLES = ("user", "employer", "admin")
STATUSES = ("active", "inactive", "pending")


def _status(raw: str) -> str:
    """The states the screen knows. Any label other than active / pending / deleted counts as inactive."""
    return raw if raw in ("active", "pending", "deleted") else "inactive"


def _actions(r) -> dict:
    """What the signed-in person may do with this account."""
    actor = g.user
    status = _status(r["status"])
    can = (str(r["id"]) != str(actor["id"]) and status != "deleted"
           and r["role"] in user_admin.ACT_ROLES[actor["role"]])
    other_admin = (actor["role"] == "admin" and r["role"] == "admin" and str(r["id"]) != str(actor["id"])
                   and status != "deleted")
    return {
        "edit": can,
        "deactivate": can and status in ("active", "pending"),
        "activate": can and status == "inactive",
        "delete": can and actor["role"] == "admin",
        "reset_password": can and status == "active",
        "reset_direct": can and status == "active" and actor["role"] == "admin",
        # another administrator's account: asking is allowed, a third administrator decides
        "request_deactivate": other_admin and status == "active",
        "request_activate": other_admin and status == "inactive",
        "request_delete": other_admin,
    }


def _pending_map(rows) -> dict:
    """Open requests for the administrator accounts among these rows. Empty before the setup script has been run."""
    ids = [r["id"] for r in rows if r["role"] == "admin"]
    if not ids:
        return {}
    try:
        return staff_accounts.pending_for(ids)
    except Exception:
        log.exception("could not read pending administrator requests")
        return {}


def _json(r, detail: bool = False, pending: dict | None = None) -> dict:
    actions = _actions(r)
    waiting = (pending or {}).get(str(r["id"]))
    if waiting:                                     # one request at a time per account
        actions.update(request_deactivate=False, request_activate=False, request_delete=False)
    out = {
        "id": str(r["id"]), "full_name": r["full_name"], "email": r["email"], "role": r["role"],
        "status": _status(r["status"]), "created_at": r["created_at"].isoformat(),
        "is_self": str(r["id"]) == str(g.user["id"]), "actions": actions, "pending_change": waiting,
    }
    if detail:
        out.update(email_verified=bool(r["is_email_verified"]),
                   last_login_at=r["last_login_at"].isoformat() if r["last_login_at"] else None,
                   scan_count=int(r["scan_count"]))
    return out


def _one(r) -> dict:
    return _json(r, detail=True, pending=_pending_map([r]))


def _find(user_id):
    """The account if this person may see it, else None (an employer asking for an employer or admin gets the same
    'not found' as for an id that does not exist)."""
    return user_admin.get_detail(g.user["role"], user_id)


def _not_allowed(r):
    if str(r["id"]) == str(g.user["id"]):
        return err("forbidden", "You cannot change your own account here.", 403)
    if r["status"] == "deleted":
        return err("forbidden", "A deleted account is kept for the records and cannot be changed.", 403)
    if r["role"] == "admin":
        return err("forbidden", "Another administrator's account cannot be changed directly. Send a request: a third "
                   "administrator has to approve it.", 403)
    return err("forbidden", "You are not allowed to change this account.", 403)


@bp.get("/users")
@auth_required("staff")
@role_required("employer", "admin")
def list_users():
    q = request.args.get("search", "").strip()[:100]
    role = request.args.get("role", "").lower()
    status = request.args.get("status", "").lower()
    deleted = request.args.get("tab", "").lower() == "deleted"
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total = user_admin.list_page(g.user["role"], q, role if role in ROLES else "",
                                       "" if deleted or status not in STATUSES else status, deleted,
                                       per_page, (page - 1) * per_page)
    pending = _pending_map(rows)
    return jsonify({"users": [_json(r, pending=pending) for r in rows], "total": total, "page": page, "per_page": per_page})


@bp.get("/users/<uuid:user_id>")
@auth_required("staff")
@role_required("employer", "admin")
def get_user(user_id):
    r = _find(user_id)
    if not r:
        return err("not_found", "Account not found.", 404)
    return jsonify({"user": _one(r)})


@bp.patch("/users/<uuid:user_id>")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def edit_user(user_id):
    r = _find(user_id)
    if not r:
        return err("not_found", "Account not found.", 404)
    if not _actions(r)["edit"]:
        return _not_allowed(r)
    full_name = " ".join(s(body(), "full_name", 100).split())
    if len(full_name) < 2:
        return err("validation", "Enter the full name.", 400, {"full_name": "Enter the full name."})
    email = user_admin.rename(g.user["role"], g.user["id"], user_id, full_name)
    if email is None:
        return err("not_found", "Account not found.", 404)
    audit.log("user_updated", "user_management", g.user["id"], {"user_id": str(user_id), "email": email})
    return jsonify({"user": _one(_find(user_id))})


@bp.post("/users/<uuid:user_id>/status")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def set_user_status(user_id):
    r = _find(user_id)
    if not r:
        return err("not_found", "Account not found.", 404)
    if not _actions(r)["edit"]:
        return _not_allowed(r)
    wanted = s(body(), "status", 10)
    if wanted not in ("active", "inactive"):
        return err("validation", "Choose active or inactive.", 400)
    activate = wanted == "active"
    outcome, info = user_admin.set_status(g.user["role"], g.user["id"], user_id, activate)
    if outcome == "not_found":
        return err("not_found", "Account not found.", 404)
    if outcome == "no_label":
        return err("setup_needed", "Deactivating accounts needs a one-time database step. Run: "
                   "python -m scripts.setup_user_management", 503)
    if outcome == "conflict":
        return err("conflict", info, 409)
    if not activate:
        sessions.revoke_all_for_user(user_id)           # signed out everywhere, now
    audit.log("user_activated" if activate else "user_deactivated", "user_management", g.user["id"],
              {"user_id": str(user_id), "email": info})
    return jsonify({"user": _one(_find(user_id))})


@bp.delete("/users/<uuid:user_id>")
@limiter.limit("30 per hour")
@auth_required("staff")
@role_required("admin")
def delete_user(user_id):
    r = _find(user_id)
    if not r:
        return err("not_found", "Account not found.", 404)
    if not _actions(r)["delete"]:
        return _not_allowed(r)
    outcome, email, permanent = user_admin.delete_account(g.user["role"], g.user["id"], user_id)
    if outcome == "not_found":
        return err("not_found", "Account not found.", 404)
    sessions.revoke_all_for_user(user_id)
    audit.log("user_deleted", "user_management", g.user["id"],
              {"user_id": str(user_id), "email": email, "permanent": permanent})
    return jsonify({"deleted": True, "permanent": permanent, "email": email})


@bp.post("/users/<uuid:user_id>/password-reset")
@limiter.limit("30 per hour")
@auth_required("staff")
@role_required("employer", "admin")
def send_password_reset(user_id):
    """An administrator resets the account now: a random temporary password is emailed and the old password stops
    working. An employer's request waits for an administrator (controllers/password_reset.py)."""
    r = _find(user_id)
    if not r:
        return err("not_found", "Account not found.", 404)
    if not _actions(r)["reset_password"]:
        return _not_allowed(r)
    if _status(r["status"]) != "active":
        return err("conflict", "Only an active account can be sent a reset.", 409)

    if g.user["role"] != "admin":
        if not pr.create_request(user_id):
            return err("conflict", "A password reset for this account is already waiting for approval.", 409)
        audit.log("password_reset_asked", "user_management", g.user["id"],
                  {"user_id": str(user_id), "email": r["email"], "role": r["role"]})
        return jsonify({"requested": True, "email": r["email"]}), 201

    temp, hours = make_temp_password(), config.TEMP_PASSWORD_HOURS
    sent = users.issue_temp_password(user_id, hash_password(temp), hours,
                                     lambda: mailer.send_reset_credentials(r["email"], r["full_name"], temp, hours))
    if not sent:
        log.error("temporary password email could not be sent")
        return err("email_failed", "The email could not be sent, so nothing was changed. Check the mail settings "
                   "in Backend/.env.", 502)
    sessions.revoke_all_for_user(user_id)
    audit.log("user_password_reset_sent", "user_management", g.user["id"],
              {"user_id": str(user_id), "email": r["email"], "kind": "temporary_password"})
    return jsonify({"sent": True, "email": r["email"]})
