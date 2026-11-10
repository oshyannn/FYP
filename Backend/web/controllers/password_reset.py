"""Forgot password: one flow for everybody, in three steps.

Public (nobody signed in)
  POST /api/auth/forgot-password              {"email"}  -> {"flow": "code" | "approval", "message"}
        normal user          : flow "code"     a 6-digit PIN is emailed now.
        employer / admin     : flow "approval" nothing is emailed; a request waits for an administrator.
  POST /api/auth/reset/verify                 {"email", "code"} -> {"ticket"}: checks the PIN. Does not change the password.
  POST /api/auth/reset/set-password           {"email", "ticket", "new_password"}: sets the new password.

Administrators (and employers for user accounts, which no longer ask this way)
  GET  /api/staff/reset-requests                          pending requests this person may decide
  POST /api/staff/reset-requests/<id>/decision            {"decision": "approve" | "reject", "note"}

Who approves
  employer accounts      : an administrator
  administrator accounts : another administrator (never the account itself)
Approving sets a RANDOM temporary password and emails it to the account's own address. The approver never sees it.
The person must choose their own password at the next login (users.must_change_password, enforced in guards.py).

The old "ask for help" endpoint (/api/auth/reset-request) and the staff-only forgot endpoint are gone: this one replaces them.
"""
from __future__ import annotations

import config
from flask import Blueprint, g, jsonify

from web import mailer
from web.controllers.common import body, err, raw, s
from web.db_models import audit, password_reset as pr, sessions, tokens, users
from web.extensions import limiter
from web.guards import auth_required
from web.security import clean_email, hash_password, make_temp_password, password_errors

bp = Blueprint("password_reset", __name__, url_prefix="/api")

BAD_CODE = "That code is invalid or has expired."
BAD_TICKET = "This reset has expired. Start again from Forgot Password."
SENT = "If this address has an account, a 6-digit PIN was sent to it."
ASKED = ("Your request was sent to an administrator for approval. Once it is approved, an email with a temporary "
         "password is sent to this address.")


def _can_decide(approver, target_id, target_role: str) -> bool:
    """The same rules as in the module docstring. Nobody decides their own account."""
    if str(approver["id"]) == str(target_id):
        return False
    if target_role == "user":
        return approver["role"] in ("employer", "admin")
    if target_role in ("employer", "admin"):
        return approver["role"] == "admin"
    return False


def _json(r) -> dict:
    return {
        "id": str(r["id"]), "status": r["status"], "created_at": r["created_at"].isoformat(),
        "account": r["full_name"] or r["email"], "email": r["email"], "role": r["role"],
        "decided_by": r["decided_by_name"], "decided_at": r["decided_at"].isoformat() if r["decided_at"] else None,
        "note": r["decision_note"],
    }


# ---- public: step 1 (email) ---------------------------------------------------------------------------------------

@bp.post("/auth/forgot-password")
@limiter.limit("5 per hour")
def forgot_password():
    """One entry for every account. Normal users get a PIN; employers and administrators get an approval request.
    The answer for an unknown, inactive or normal-user address is the same 'code' answer, so only employer and
    administrator addresses are told apart (the screen has to say something different for them)."""
    email, _ = clean_email(s(body(), "email", 254))
    user = users.get_by_email(email) if email else None
    if user and user["status"] == "active" and user["role"] in ("employer", "admin"):
        if pr.create_request(user["id"]):
            audit.log("password_reset_asked", "auth", user["id"], {"role": user["role"]})
        return jsonify({"flow": "approval", "message": ASKED}), 202
    if (user and user["status"] == "active" and user["role"] == "user"
            and not tokens.recently_issued(user["id"], "password_reset", config.CODE_RESEND_SECONDS)):
        mailer.send_reset_code(user["email"], tokens.issue_code(user["id"], "password_reset", config.RESET_CODE_MINUTES))
        audit.log("password_reset_requested", "auth", user["id"])
    return jsonify({"flow": "code", "message": SENT}), 202


# ---- public: step 2 (check the PIN) and step 3 (set the password) -------------------------------------------------

@bp.post("/auth/reset/verify")
@limiter.limit("20 per hour")
def verify_reset_code():
    data = body()
    email, _ = clean_email(s(data, "email", 254))
    user = users.get_by_email(email) if email else None
    if not user or user["status"] != "active" or not tokens.verify_code(user["id"], "password_reset", s(data, "code", 10)):
        return err("invalid_code", BAD_CODE, 400)
    audit.log("password_reset_code_ok", "auth", user["id"])
    return jsonify({"ticket": pr.issue_ticket(user["id"])})


@bp.post("/auth/reset/set-password")
@limiter.limit("10 per hour")
def set_password_with_ticket():
    data = body()
    email, _ = clean_email(s(data, "email", 254))
    user = users.get_by_email(email) if email else None
    new_pw = raw(data, "new_password")
    errs = password_errors(new_pw, email or "", (user["full_name"] or "") if user else "")
    if errs:                                     # checked first: a weak password does not use up the ticket
        return err("validation", "Please correct the highlighted fields.", 400, {"new_password": " ".join(errs)})
    ticket = s(data, "ticket", 200)
    if not user or user["status"] != "active" or not ticket or not pr.consume_ticket(user["id"], ticket):
        return err("invalid_ticket", BAD_TICKET, 400)
    users.set_password(user["id"], hash_password(new_pw))
    sessions.revoke_all_for_user(user["id"])       # every device and paired extension is signed out
    audit.log("password_reset", "auth", user["id"], {"via": "ticket"})
    return jsonify({"message": "Password updated. Log in with your new password."})


# ---- staff: approve or reject ---------------------------------------------------------------------------------------

@bp.get("/staff/reset-requests")
@auth_required("staff")
def list_reset_requests():
    if g.user["role"] not in ("employer", "admin"):
        return err("forbidden", "Not available for this account.", 403)
    rows = pr.list_pending(g.user["id"], g.user["role"])
    return jsonify({"requests": [_json(r) for r in rows]})


@bp.post("/staff/reset-requests/<uuid:req_id>/decision")
@limiter.limit("60 per hour")
@auth_required("staff")
def decide_reset_request(req_id):
    if g.user["role"] not in ("employer", "admin"):
        return err("forbidden", "Not available for this account.", 403)
    data = body()
    decision = s(data, "decision", 10)
    if decision not in ("approve", "reject"):
        return err("validation", "Choose approve or reject.", 400)
    req = pr.get(req_id)
    if not req:
        return err("not_found", "Request not found.", 404)
    if req["status"] != "pending":
        return err("conflict", "This request has already been decided.", 409)
    if not _can_decide(g.user, req["user_id"], req["role"]):
        return err("forbidden", "You cannot decide this request. An administrator decides for employers, and "
                   "another administrator decides for administrators.", 403)
    account = users.get_by_id(req["user_id"])
    if not account or account["status"] != "active":
        return err("conflict", "This account is no longer active.", 409)
    note = s(data, "note", 1000)

    if decision == "reject":
        if not pr.mark_decided(req_id, g.user["id"], "rejected", note):
            return err("conflict", "This request has already been decided.", 409)
        audit.log("password_reset_rejected", "user_management", g.user["id"], {"email": req["email"], "role": req["role"]})
        return jsonify({"decided": "rejected"})

    temp, hours = make_temp_password(), config.TEMP_PASSWORD_HOURS
    outcome = pr.approve_with_temp_password(
        req_id, g.user["id"], account["id"], hash_password(temp), hours, note,
        lambda: mailer.send_reset_credentials(account["email"], account["full_name"], temp, hours))
    if outcome == "conflict":
        return err("conflict", "This request has already been decided.", 409)
    if outcome == "email_failed":
        return err("email_failed", "The email could not be sent, so nothing was changed. Check the mail settings in "
                   "Backend/.env. The request stays pending.", 502)
    sessions.revoke_all_for_user(account["id"])    # the old password and every open session stop working now
    audit.log("password_reset_approved", "user_management", g.user["id"], {"email": req["email"], "role": req["role"]})
    return jsonify({"decided": "approved"})
