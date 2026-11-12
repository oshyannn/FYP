"""Creating employer and administrator accounts, and changing ANOTHER administrator's account, with approvals.

Administrator only
  POST /api/staff/invitations                      {"full_name", "email", "role": "employer" | "admin"}
  GET  /api/staff/invitations                      ?status= &page= &per_page=
  POST /api/staff/invitations/<id>/revoke
  POST /api/staff/invitations/<id>/decision        {"decision": "approve" | "reject", "note"}   (admin invitations only)
  POST /api/staff/admin-changes                    {"user_id", "action": "deactivate" | "activate" | "delete"}
  POST /api/staff/admin-changes/<id>/decision      {"decision": "approve" | "reject", "note"}
  GET  /api/staff/approvals                        what waits for a decision, and the latest decisions
Nobody signed in
  POST /api/staff/accept-invite                    {"email", "code", "pin", "password"}

Rules
  - The address is checked BEFORE anything is emailed: one that already has an account, or an open invitation, is refused.
  - An employer invitation is emailed at once (a 6-digit code). An administrator invitation waits for ANOTHER administrator
    and also has a PIN, shown to the inviter once and never emailed; accepting needs the emailed code and the PIN.
  - The account is created only when the invitation is accepted, with the person's own password.
  - A change to another administrator's account needs a third administrator: not the requester and not that account.
  - Employer sign-up on the login screen is closed (the old route answers 410).
"""
from __future__ import annotations

import logging
import uuid

import config
from flask import Blueprint, g, jsonify, request

from web import mailer
from web.controllers.common import body, err, int_arg, raw, s
from web.db_models import audit, sessions, staff_accounts, users
from web.extensions import limiter
from web.guards import auth_required, role_required
from web.security import (clean_email, code_hash, hash_password, make_code, make_temp_password, make_username,
                          password_errors)

log = logging.getLogger(__name__)
bp = Blueprint("staff_accounts", __name__, url_prefix="/api/staff")

INVITE_HOURS = 24
INVITE_STATUSES = ("awaiting_approval", "sent", "accepted", "revoked", "rejected", "expired", "locked")
CHANGE_ACTIONS = ("deactivate", "activate", "delete")
BAD_INVITE = "That invitation is invalid, expired, or the details do not match."


@bp.before_app_request
def _staff_signup_is_closed():
    """Employers no longer apply on their own. Answered here so the old route in api_auth.py cannot be reached."""
    if request.path == "/api/staff/request-access":
        return err("closed", "Employer sign-up is closed. An administrator creates staff accounts and sends an "
                   "invitation by email.", 410)
    return None


def _who(name, email) -> str:
    return name or email or "—"


def _inv_json(r) -> dict:
    return {
        "id": str(r["id"]), "email": r["email"], "full_name": r["full_name"], "role": r["role"], "status": r["status"],
        "invited_by": _who(r["invited_by_name"], r["invited_by_email"]),
        "created_at": r["created_at"].isoformat(),
        "expires_at": r["code_expires_at"].isoformat() if r["code_expires_at"] and r["status"] == "sent" else None,
        "accepted_at": r["accepted_at"].isoformat() if r["accepted_at"] else None,
    }


def _change_json(r) -> dict:
    me = str(g.user["id"])
    return {
        "id": str(r["id"]), "action": r["action"], "status": r["status"], "created_at": r["created_at"].isoformat(),
        "decided_at": r["decided_at"].isoformat() if r["decided_at"] else None, "note": r["decision_note"],
        "target": _who(r["target_name"], r["target_email"]), "target_email": r["target_email"],
        "requested_by": _who(r["requested_by_name"], r["requested_by_email"]),
        "decided_by": r["decided_by_name"],
        # the page only shows Approve / Reject when the server would accept it
        "can_decide": r["status"] == "pending" and me not in (str(r["target_id"]), str(r["requested_by_id"])),
    }


# ---- invitations -----------------------------------------------------------------------------------------------

@bp.post("/invitations")
@limiter.limit("20 per hour")
@auth_required("staff")
@role_required("admin")
def create_invitation():
    data = body()
    name = " ".join(s(data, "full_name", 100).split())
    email, email_err = clean_email(s(data, "email", 254))
    role = s(data, "role", 10)
    fields: dict[str, str] = {}
    if len(name) < 2:
        fields["full_name"] = "Enter the full name."
    if email_err:
        fields["email"] = email_err
    if role not in ("employer", "admin"):
        fields["role"] = "Choose Employer or Admin."
    if fields:
        return err("validation", "Please correct the highlighted fields.", 400, fields)

    if role == "employer":
        # No invitation, no code, no link: the account is created now with a random temporary password that is emailed.
        temp, hours = make_temp_password(), config.TEMP_PASSWORD_HOURS
        outcome, uid = users.create_employer(email, name, hash_password(temp), hours,
                                             lambda: mailer.send_employer_credentials(email, name, temp, hours))
        if outcome == "taken":
            return err("conflict", "This email address already has an account.", 409, {"email": "Already has an account."})
        if outcome == "open":
            return err("conflict", "This address has an open administrator invitation. Revoke it first.", 409,
                       {"email": "Already invited."})
        if outcome == "email_failed":
            log.error("employer credentials email could not be sent")
            return err("email_failed", "The email could not be sent, so no account was created. Check the mail "
                       "settings in Backend/.env.", 502)
        audit.log("employer_created", "user_management", g.user["id"], {"email": email, "user_id": str(uid)})
        return jsonify({"account": {"id": str(uid), "email": email, "full_name": name, "role": "employer"},
                        "expires_in_hours": hours}), 201

    code = pin = code_h = pin_h = None
    if role == "employer":
        code = make_code()
        code_h = code_hash(f"invite|{email}", code)
    else:
        pin = make_code()
        pin_h = code_hash(f"invite-pin|{email}", pin)

    outcome, row = staff_accounts.create_invitation(g.user["id"], email, name, role, code_h, pin_h, INVITE_HOURS)
    if outcome == "taken":                                      # checked before anything is sent
        return err("conflict", "This email address already has an account.", 409, {"email": "Already has an account."})
    if outcome == "open":
        return err("conflict", "This address already has an invitation that is still open. Revoke it first to send a new one.",
                   409, {"email": "Already invited."})
    if role == "employer" and not mailer.send_staff_invite(email, name, role, code, INVITE_HOURS):
        staff_accounts.discard_invitation(row["id"])
        log.error("staff invitation email could not be sent")
        return err("email_failed", "The email could not be sent. Check the mail settings in Backend/.env.", 502)
    audit.log("staff_invite_created", "user_management", g.user["id"], {"email": email, "role": role})
    out = {"invitation": _inv_json(staff_accounts.get_invitation(row["id"]))}
    if pin:
        out["pin"] = pin                                        # shown to the inviter once, never stored in clear text
    return jsonify(out), 201


@bp.get("/invitations")
@auth_required("staff")
@role_required("admin")
def list_invitations():
    status = request.args.get("status", "").lower()
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total = staff_accounts.list_invitations(status if status in INVITE_STATUSES else "", per_page, (page - 1) * per_page)
    return jsonify({"invitations": [_inv_json(r) for r in rows], "total": total, "page": page, "per_page": per_page})


@bp.post("/invitations/<uuid:inv_id>/revoke")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("admin")
def revoke_invitation(inv_id):
    outcome, info = staff_accounts.revoke_invitation(inv_id, g.user["id"])
    if outcome == "not_found":
        return err("not_found", "Invitation not found.", 404)
    if outcome == "conflict":
        return err("conflict", info, 409)
    audit.log("staff_invite_revoked", "user_management", g.user["id"], {"email": info})
    return jsonify({"invitation": _inv_json(staff_accounts.get_invitation(inv_id))})


@bp.post("/invitations/<uuid:inv_id>/decision")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("admin")
def decide_invitation(inv_id):
    data = body()
    decision = s(data, "decision", 10)
    if decision not in ("approve", "reject"):
        return err("validation", "Choose approve or reject.", 400)
    inv = staff_accounts.get_invitation(inv_id)
    if not inv or inv["role"] != "admin":
        return err("not_found", "Invitation not found.", 404)
    if inv["status"] != "awaiting_approval":
        return err("conflict", "This invitation is not waiting for approval.", 409)
    if inv["invited_by_id"] is not None and str(inv["invited_by_id"]) == str(g.user["id"]):
        return err("forbidden", "Another administrator has to decide this. You cannot approve your own invitation.", 403)
    code = code_h = None
    if decision == "approve":                                   # the only moment an admin invitation is emailed
        code = make_code()
        code_h = code_hash(f"invite|{inv['email']}", code)
        if not mailer.send_staff_invite(inv["email"], inv["full_name"], "admin", code, INVITE_HOURS):
            log.error("staff invitation email could not be sent")
            return err("email_failed", "The email could not be sent. Check the mail settings in Backend/.env. "
                       "The invitation stays waiting for approval.", 502)
    outcome, info = staff_accounts.decide_invitation(inv_id, g.user["id"], decision == "approve", s(data, "note", 1000),
                                                     code_h, INVITE_HOURS)
    if outcome == "not_found":
        return err("not_found", "Invitation not found.", 404)
    if outcome == "same_person":
        return err("forbidden", "Another administrator has to decide this.", 403)
    if outcome == "conflict":
        return err("conflict", info, 409)
    audit.log("staff_invite_approved" if decision == "approve" else "staff_invite_rejected", "user_management",
              g.user["id"], {"email": info["email"]})
    return jsonify({"invitation": _inv_json(staff_accounts.get_invitation(inv_id))})


# ---- changes to ANOTHER administrator's account ---------------------------------------------------------------

@bp.post("/admin-changes")
@limiter.limit("30 per hour")
@auth_required("staff")
@role_required("admin")
def request_admin_change():
    data = body()
    action = s(data, "action", 12)
    try:
        target = uuid.UUID(s(data, "user_id", 40))
    except ValueError:
        return err("validation", "Choose an administrator account.", 400)
    if action not in CHANGE_ACTIONS:
        return err("validation", "Choose deactivate, activate or delete.", 400)
    outcome, info = staff_accounts.create_change(target, action, g.user["id"])
    if outcome == "not_found":
        return err("not_found", "Administrator account not found.", 404)
    if outcome == "conflict":
        return err("conflict", info, 409)
    audit.log("admin_change_requested", "user_management", g.user["id"], {"email": info["email"], "action": action})
    return jsonify({"requested": True, "id": str(info["id"])}), 201


@bp.post("/admin-changes/<uuid:change_id>/decision")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("admin")
def decide_admin_change(change_id):
    data = body()
    decision = s(data, "decision", 10)
    if decision not in ("approve", "reject"):
        return err("validation", "Choose approve or reject.", 400)
    outcome, info = staff_accounts.decide_change(change_id, g.user["id"], decision == "approve", s(data, "note", 1000))
    if outcome == "not_found":
        return err("not_found", "Request not found.", 404)
    if outcome == "same_person":
        return err("forbidden", "A third administrator has to decide this: not the one who asked, and not the account itself.", 403)
    if outcome == "no_label":
        return err("setup_needed", "Deactivating accounts needs a one-time database step. Run: "
                   "python -m scripts.setup_user_management", 503)
    if outcome == "conflict":
        return err("conflict", info, 409)
    audit.log("admin_change_approved" if decision == "approve" else "admin_change_rejected", "user_management",
              g.user["id"], {"email": info["email"], "action": info["action"]})
    if decision == "approve":
        if info["action"] in ("deactivate", "delete"):
            sessions.revoke_all_for_user(info["target_id"])     # signed out everywhere, now
        audit.log({"deactivate": "user_deactivated", "activate": "user_activated", "delete": "user_deleted"}[info["action"]],
                  "user_management", g.user["id"], {"user_id": str(info["target_id"]), "email": info["email"]})
    return jsonify({"decided": decision})


@bp.get("/approvals")
@auth_required("staff")
@role_required("admin")
def approvals():
    """What waits for this administrator, and the latest decisions."""
    items = []
    for r in staff_accounts.approval_invitations():
        j = _inv_json(r)
        items.append({
            "kind": "invitation", "id": j["id"], "status": r["status"], "created_at": j["created_at"],
            "title": "New administrator account", "detail": f"{r['full_name']} ({r['email']})",
            "requested_by": j["invited_by"], "decided_by": r["decided_by_name"],
            "can_decide": r["status"] == "awaiting_approval" and str(r["invited_by_id"]) != str(g.user["id"]),
        })
    for r in staff_accounts.list_changes():
        j = _change_json(r)
        items.append({
            "kind": "change", "id": j["id"], "status": r["status"], "created_at": j["created_at"],
            "title": {"deactivate": "Deactivate administrator", "activate": "Activate administrator",
                      "delete": "Delete administrator"}[r["action"]],
            "detail": f"{j['target']}" + (f" ({j['target_email']})" if j["target"] != j["target_email"] else ""),
            "requested_by": j["requested_by"], "decided_by": j["decided_by"], "can_decide": j["can_decide"],
        })
    waiting = sorted((i for i in items if i["status"] in ("pending", "awaiting_approval")),
                     key=lambda i: i["created_at"], reverse=True)
    done = sorted((i for i in items if i["status"] not in ("pending", "awaiting_approval")),
                  key=lambda i: i["created_at"], reverse=True)[:20]
    return jsonify({"items": waiting + done, "waiting": len(waiting),
                    "waiting_for_me": sum(1 for i in waiting if i["can_decide"])})


# ---- accepting an invitation (nobody is signed in) --------------------------------------------------------------

@bp.post("/accept-invite")
@limiter.limit("5 per minute; 20 per hour")
def accept_invite():
    data = body()
    email, _ = clean_email(s(data, "email", 254))
    code, pin, password = s(data, "code", 10), s(data, "pin", 10), raw(data, "password")
    if not email or not code or len(code) != 6 or not code.isdigit():
        return err("invalid_invite", BAD_INVITE, 400)
    # Rules that do not depend on the invitation come first, so this answer never says whether one exists.
    early = password_errors(password, email, "")
    if early:
        return err("validation", "Please correct the highlighted fields.", 400, {"password": " ".join(early)})
    outcome, info = staff_accounts.accept_invitation(
        email, code, pin, hash_password(password), make_username(email),
        lambda name: password_errors(password, email, name))
    if outcome == "invalid":
        audit.log("staff_invite_failed", "user_management", None, {})
        return err("invalid_invite", BAD_INVITE, 400)
    if outcome == "taken":
        return err("invalid_invite", BAD_INVITE, 400)
    if outcome == "weak":
        return err("validation", "Please correct the highlighted fields.", 400, {"password": " ".join(info)})
    audit.log("staff_invite_accepted", "user_management", info["user_id"], {"email": email, "role": info["role"]})
    return jsonify({"message": "Your account is ready. Sign in with your email and your new password.", "role": info["role"]})
