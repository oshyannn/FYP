"""Bearer-token authentication and access control for the JSON API. Checked against the database every request."""
from __future__ import annotations

from functools import wraps

from flask import g, jsonify, request

from models import sessions
from security import hash_token


def _bearer() -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        token = header[7:].strip()
        if 20 <= len(token) <= 100:
            return token
    return None


def load_current_user() -> None:
    """Sets g.user from the Authorization header, or leaves it None. Role and status come from the DB every time."""
    g.user = None
    token = _bearer()
    if not token:
        return
    row = sessions.get_active(hash_token(token))
    if not row:
        return
    portal_mismatch = (
        (row["portal"] in ("user", "extension") and row["role"] != "user")
        or (row["portal"] == "staff" and row["role"] not in ("employer", "admin"))
    )
    if row["status"] != "active" or not row["is_email_verified"] or portal_mismatch:
        sessions.revoke(row["sid"])          # suspended, demoted or promoted: the old session dies at once
        return
    sessions.touch(row["sid"])
    g.user = row


def _deny(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def auth_required(*portals: str):
    """The caller must be logged in through one of these portals ('user', 'staff', 'extension')."""
    def deco(view):
        @wraps(view)
        def wrapped(*a, **k):
            if g.user is None:
                return _deny("unauthenticated", "Please log in.", 401)
            if g.user["portal"] not in portals:
                return _deny("forbidden", "This account cannot use this function.", 403)
            return view(*a, **k)
        return wrapped
    return deco


def role_required(*roles: str):
    def deco(view):
        @wraps(view)
        def wrapped(*a, **k):
            if g.user is None:
                return _deny("unauthenticated", "Please log in.", 401)
            if g.user["role"] not in roles:
                return _deny("forbidden", "You do not have permission for this function.", 403)
            return view(*a, **k)
        return wrapped
    return deco
