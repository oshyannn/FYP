"""JSON API for the desktop application and the browser extension (authentication + account).

Users           POST /api/auth/register | verify-email | resend-code | login | forgot-password | reset-password
Employer/admin  POST /api/staff/login | request-access | forgot-password        (separate endpoints, separate rules)
Account         GET/PATCH /api/me,  POST /api/me/password,  POST /api/auth/logout
Extension       POST /api/extension/pairing-code (desktop)  ->  POST /api/extension/pair (extension)
                GET /api/extension/devices, DELETE /api/extension/devices/<id>   (desktop, to revoke an extension)

There is deliberately NO endpoint that creates an admin. An employer is an ordinary user until an
administrator approves the application, and the database blocks any admin/employer insert or promotion
unless the server opts in (see scripts/staff_admin.py).
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

import config
import mailer
from extensions import limiter
from guards import auth_required
from models import audit, sessions, tokens, users
from security import (DUMMY_HASH, clean_email, hash_password, hash_token, needs_rehash, new_token,
                      normalize_pairing_code, password_errors, verify_password)

bp = Blueprint("api", __name__, url_prefix="/api")

GENERIC_LOGIN_ERROR = "Incorrect email or password, or the account is temporarily locked."
BAD_CODE = "That code is invalid or has expired."
PORTAL_ROLES = {"user": ("user",), "staff": ("employer", "admin")}   # who may sign in where


# ---------------------------------------------------------------- helpers
def _err(code: str, message: str, status: int, fields: dict | None = None):
    body = {"error": {"code": code, "message": message}}
    if fields:
        body["error"]["fields"] = fields
    return jsonify(body), status


def _body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _s(data: dict, key: str, maxlen: int = 256) -> str:
    v = data.get(key)
    return v.strip()[:maxlen] if isinstance(v, str) else ""


def _raw(data: dict, key: str, maxlen: int = 128) -> str:        # passwords are never trimmed
    v = data.get(key)
    return v[:maxlen] if isinstance(v, str) else ""


def _user_json(u) -> dict:
    return {"id": str(u["id"]), "email": u["email"], "full_name": u["full_name"], "role": u["role"]}


def _accepted(message: str):
    return jsonify({"message": message}), 202


def _read_signup(data: dict):
    full_name = " ".join(_s(data, "full_name", 100).split())
    email, email_err = clean_email(_s(data, "email", 254))
    password = _raw(data, "password")
    errors = {}
    if len(full_name) < 2:
        errors["full_name"] = "Enter your full name."
    if email_err:
        errors["email"] = email_err
    pw_errs = password_errors(password, email or "", full_name)
    if pw_errs:
        errors["password"] = " ".join(pw_errs)
    return {"full_name": full_name, "email": email, "password": password}, errors


def _send_verification(user_id, email: str) -> None:
    """One email with both ways to verify: a 6-digit code and a link."""
    code = tokens.issue_code(user_id, "email_verification", config.VERIFY_CODE_MINUTES)
    link = f"{config.BASE_URL}/verify/{tokens.issue_link(user_id, config.VERIFY_LINK_HOURS)}"
    mailer.send_verification_code(email, code, link)


def _challenge_of(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _register(form: dict, employer: dict | None = None, challenge: str = "") -> None:
    pw_hash = hash_password(form["password"])        # hash first so timing does not reveal existing emails
    uid = users.create_user(form["email"], form["full_name"], pw_hash)
    if uid is None:
        audit.log("register_duplicate", "auth")
        return
    if employer:
        users.create_employer_application(uid, employer["company_name"], employer["company_registration_no"])
    if challenge:
        tokens.issue_handoff(uid, challenge, config.HANDOFF_MINUTES)
    _send_verification(uid, form["email"])
    audit.log("register", "auth", uid, {"employer_application": bool(employer)})


def _new_session(user, portal: str, remember: bool = False) -> dict:
    if portal == "staff":
        hours, idle = config.STAFF_SESSION_HOURS, config.STAFF_IDLE_MINUTES
    elif remember:
        hours, idle = config.REMEMBER_DAYS * 24, config.REMEMBER_IDLE_DAYS * 1440
    else:
        hours, idle = config.USER_SESSION_HOURS, config.USER_IDLE_MINUTES
    token = new_token()
    sessions.create(user["id"], portal, hash_token(token), hours, idle, request.remote_addr,
                    (request.user_agent.string or "")[:300])
    return {"token": token, "expires_in": hours * 3600, "portal": portal, "user": _user_json(user)}


# ---------------------------------------------------------------- login (one function, two separate endpoints)
def _login(portal: str):
    data = _body()
    email, _ = clean_email(_s(data, "email", 254))
    password = _raw(data, "password")
    user = users.get_by_email(email) if email else None

    # Always run one password verification, so response time does not reveal whether the account exists.
    password_ok = verify_password(user["password_hash"] if user else DUMMY_HASH, password) and user is not None
    locked = bool(user and user["locked_until"] and user["locked_until"] > datetime.now(timezone.utc))
    right_portal = bool(user and user["role"] in PORTAL_ROLES[portal])

    if not (password_ok and right_portal) or locked:
        if user and not locked:
            users.record_failed_login(user["id"])
        audit.log("login_failed", "auth", user["id"] if user else None, {"portal": portal, "locked": locked})
        return _err("invalid_credentials", GENERIC_LOGIN_ERROR, 401)

    if user["status"] == "pending" and not user["is_email_verified"]:
        if not tokens.recently_issued(user["id"], "email_verification", config.CODE_RESEND_SECONDS):
            _send_verification(user["id"], user["email"])
        audit.log("login_unverified", "auth", user["id"], {"portal": portal})
        return _err("email_not_verified", "Verify your email first. We sent a 6-digit code to your inbox.", 403)
    if user["status"] != "active":
        audit.log("login_blocked", "auth", user["id"], {"portal": portal, "status": user["status"]})
        return _err("invalid_credentials", GENERIC_LOGIN_ERROR, 401)

    users.record_login_success(user["id"])
    if needs_rehash(user["password_hash"]):
        users.update_hash(user["id"], hash_password(password))
    result = _new_session(user, portal, remember=(portal == "user" and data.get("remember") is True))
    audit.log("login_success", "auth", user["id"], {"portal": portal})
    return jsonify(result)


@bp.post("/auth/login")
@limiter.limit("10 per minute; 60 per hour")
def user_login():
    return _login("user")


@bp.post("/staff/login")
@limiter.limit("10 per minute; 60 per hour")
def staff_login():
    return _login("staff")


# ---------------------------------------------------------------- registration
@bp.post("/auth/register")
@limiter.limit("5 per hour")
def user_register():
    """Creates role 'user' only. The server never reads a role from the request."""
    form, errors = _read_signup(_body())
    if errors:
        return _err("validation", "Please correct the highlighted fields.", 400, errors)
    challenge = _s(_body(), "client_challenge", 64).lower()        # sha256 of a secret the app keeps in memory
    _register(form, challenge=challenge if re.fullmatch(r"[0-9a-f]{64}", challenge) else "")
    return _accepted("If this address can be registered, we sent an email with a link and a 6-digit code.")


@bp.post("/staff/request-access")
@limiter.limit("5 per hour")
def staff_request_access():
    """Employer application: a normal user plus a pending verification that an administrator must approve."""
    data = _body()
    form, errors = _read_signup(data)
    company = " ".join(_s(data, "company_name", 100).split())
    reg_no = _s(data, "company_registration_no", 50)
    if len(company) < 2:
        errors["company_name"] = "Enter your company name."
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ./()\-]{2,49}", reg_no):
        errors["company_registration_no"] = "Use 3-50 letters, numbers, spaces or - . / ( )."
    if errors:
        return _err("validation", "Please correct the highlighted fields.", 400, errors)
    _register(form, employer={"company_name": company, "company_registration_no": reg_no})
    return _accepted("Check your email to verify your address. After that, an administrator reviews your company details.")


# ---------------------------------------------------------------- email verification
@bp.post("/auth/verify-email")
@limiter.limit("20 per hour")
def verify_email():
    """Verify with the 6-digit code. If the app that started the sign-up sends its device_secret, it is logged in."""
    data = _body()
    email, _ = clean_email(_s(data, "email", 254))
    user = users.get_by_email(email) if email else None
    if not user or not tokens.verify_code(user["id"], "email_verification", _s(data, "code", 10)):
        return _err("invalid_code", BAD_CODE, 400)
    users.mark_verified(user["id"])
    audit.log("email_verified", "auth", user["id"], {"via": "code"})
    portal = "staff" if user["role"] in PORTAL_ROLES["staff"] else "user"
    result = {"message": "Email verified. You can now log in.", "portal": portal}
    secret = _s(data, "device_secret", 128)
    if portal == "user" and len(secret) >= 32 and tokens.consume_handoff(user["id"], _challenge_of(secret)):
        result.update(_new_session(user, "user"))
    return jsonify(result)


@bp.post("/auth/complete-signup")
@limiter.limit("40 per minute")
def complete_signup():
    """The app polls this after register. Pending until the email is verified (link or code), then it signs in."""
    data = _body()
    email, _ = clean_email(_s(data, "email", 254))
    secret = _s(data, "device_secret", 128)
    user = users.get_by_email(email) if email else None
    challenge = _challenge_of(secret) if len(secret) >= 32 else ""
    if not user or user["role"] != "user" or not challenge or not tokens.has_handoff(user["id"], challenge):
        return _err("invalid_request", "This sign-up can no longer be completed. Log in with your password.", 400)
    if not user["is_email_verified"] or user["status"] != "active":
        return jsonify({"status": "pending"}), 202
    if not tokens.consume_handoff(user["id"], challenge):
        return _err("invalid_request", "This sign-up can no longer be completed. Log in with your password.", 400)
    audit.log("signup_completed", "auth", user["id"])
    return jsonify(_new_session(user, "user"))


@bp.post("/auth/resend-code")
@limiter.limit("5 per hour")
def resend_code():
    email, _ = clean_email(_s(_body(), "email", 254))
    user = users.get_by_email(email) if email else None
    if (user and user["status"] == "pending" and not user["is_email_verified"]
            and not tokens.recently_issued(user["id"], "email_verification", config.CODE_RESEND_SECONDS)):
        _send_verification(user["id"], user["email"])
    return _accepted("If that account is waiting for verification, we sent a new email.")


# ---------------------------------------------------------------- password recovery
def _forgot(portal: str):
    email, _ = clean_email(_s(_body(), "email", 254))
    user = users.get_by_email(email) if email else None
    if (user and user["status"] == "active" and user["role"] in PORTAL_ROLES[portal]
            and not tokens.recently_issued(user["id"], "password_reset", config.CODE_RESEND_SECONDS)):
        mailer.send_reset_code(user["email"], tokens.issue_code(user["id"], "password_reset", config.RESET_CODE_MINUTES))
        audit.log("password_reset_requested", "auth", user["id"])
    return _accepted("If an account exists for that address, we sent a 6-digit reset code.")


@bp.post("/auth/forgot-password")
@limiter.limit("5 per hour")
def user_forgot():
    return _forgot("user")


@bp.post("/staff/forgot-password")
@limiter.limit("5 per hour")
def staff_forgot():
    return _forgot("staff")


@bp.post("/auth/reset-password")
@limiter.limit("10 per hour")
def reset_password():
    data = _body()
    email, _ = clean_email(_s(data, "email", 254))
    user = users.get_by_email(email) if email else None
    new_pw = _raw(data, "new_password")
    errs = password_errors(new_pw, email or "", (user["full_name"] or "") if user else "")
    if errs:
        return _err("validation", "Please correct the highlighted fields.", 400, {"new_password": " ".join(errs)})
    if not user or user["status"] != "active" or not tokens.verify_code(user["id"], "password_reset", _s(data, "code", 10)):
        return _err("invalid_code", BAD_CODE, 400)
    users.set_password(user["id"], hash_password(new_pw))
    sessions.revoke_all_for_user(user["id"])          # every device and paired extension is logged out
    audit.log("password_reset", "auth", user["id"])
    return jsonify({"message": "Password updated. Log in with your new password."})


# ---------------------------------------------------------------- account
@bp.post("/auth/logout")
@auth_required("user", "staff", "extension")
def logout():
    sessions.revoke(g.user["sid"])
    audit.log("logout", "auth", g.user["id"], {"portal": g.user["portal"]})
    return jsonify({"message": "Logged out."})


@bp.get("/me")
@auth_required("user", "staff", "extension")
def me():
    return jsonify({"user": _user_json(g.user), "portal": g.user["portal"]})


@bp.patch("/me")
@auth_required("user", "staff")
def update_me():
    full_name = " ".join(_s(_body(), "full_name", 100).split())
    if len(full_name) < 2:
        return _err("validation", "Please correct the highlighted fields.", 400, {"full_name": "Enter your full name."})
    users.update_full_name(g.user["id"], full_name)
    audit.log("profile_updated", "account", g.user["id"])
    return jsonify({"user": {**_user_json(g.user), "full_name": full_name}})


@bp.post("/me/password")
@auth_required("user", "staff")
@limiter.limit("10 per hour")
def change_password():
    data = _body()
    user = users.get_by_id(g.user["id"])
    if not verify_password(user["password_hash"], _raw(data, "current_password")):
        return _err("invalid_credentials", "Your current password is incorrect.", 400)
    new_pw = _raw(data, "new_password")
    errs = password_errors(new_pw, user["email"], user["full_name"] or "")
    if errs:
        return _err("validation", "Please correct the highlighted fields.", 400, {"new_password": " ".join(errs)})
    users.set_password(user["id"], hash_password(new_pw))
    sessions.revoke_all_for_user(user["id"], except_sid=g.user["sid"])     # other devices are logged out
    audit.log("password_changed", "account", user["id"])
    return jsonify({"message": "Password updated."})


# ---------------------------------------------------------------- extension pairing
@bp.post("/extension/pairing-code")
@limiter.limit("10 per hour")
@auth_required("user")
def pairing_code():
    """Called by the desktop app. The extension never registers or logs in with a password."""
    code = tokens.issue_pairing_code(g.user["id"], config.PAIRING_CODE_MINUTES)
    audit.log("pairing_code_issued", "extension", g.user["id"])
    return jsonify({"code": f"{code[:4]}-{code[4:]}", "expires_in": config.PAIRING_CODE_MINUTES * 60})


@bp.post("/extension/pair")
@limiter.limit("10 per minute; 30 per hour")
def pair_extension():
    """Called by the extension with the code shown in the desktop app. Returns the extension's own token."""
    data = _body()
    code = normalize_pairing_code(_s(data, "code", 20))
    uid = tokens.consume_pairing_code(code) if code else None
    user = users.get_by_id(uid) if uid else None
    if not user or user["status"] != "active" or user["role"] != "user":
        return _err("invalid_code", "That pairing code is invalid or has expired.", 400)
    label = _s(data, "device_name", 100) or "Browser extension"
    token = new_token()
    sessions.create(user["id"], "extension", hash_token(token), config.EXT_SESSION_DAYS * 24,
                    config.EXT_IDLE_DAYS * 1440, request.remote_addr, (request.user_agent.string or "")[:300], label)
    audit.log("extension_paired", "extension", user["id"], {"label": label})
    return jsonify({"token": token, "expires_in": config.EXT_SESSION_DAYS * 86400,
                    "user": {"full_name": user["full_name"], "email": user["email"]}})


@bp.get("/extension/devices")
@auth_required("user")
def extension_devices():
    rows = sessions.list_extensions(g.user["id"])
    return jsonify({"devices": [{"id": str(r["id"]), "label": r["label"],
                                 "paired_at": r["created_at"].isoformat(),
                                 "last_seen_at": r["last_seen_at"].isoformat()} for r in rows]})


@bp.delete("/extension/devices/<uuid:session_id>")
@auth_required("user")
def revoke_extension(session_id):
    if not sessions.revoke_extension(session_id, g.user["id"]):
        return _err("not_found", "Device not found.", 404)
    audit.log("extension_revoked", "extension", g.user["id"])
    return jsonify({"message": "Extension disconnected."})
