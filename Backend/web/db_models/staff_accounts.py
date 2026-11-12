"""Staff invitations and administrator approvals (Model layer).

staff_invitations     an administrator invites an employer or an administrator by email.
                      employer invitation : sent at once, a 6-digit code by email.
                      admin invitation    : first 'awaiting_approval' (nothing is emailed), another administrator decides;
                                            on approval the code is emailed. It also has a PIN the inviter tells the person
                                            by phone or chat; accepting needs the emailed code AND the PIN.
                      The invited person sets their own password. The account is created only when the invitation is
                      accepted, so a mistyped address never leaves a half-made account behind.
admin_change_requests one administrator asks to deactivate, activate or delete ANOTHER administrator's account; a third
                      administrator (neither the requester nor the account itself) approves or rejects it.
"""
from __future__ import annotations

import hmac

import config
from web import db
from web.db_models import user_admin
from web.security import code_hash

_INV = """
SELECT i.id, i.email, i.full_name, i.role,
       CASE WHEN i.status = 'sent' AND i.code_expires_at < now() THEN 'expired' ELSE i.status END AS status,
       i.created_at, i.code_expires_at, i.accepted_at, i.decided_at, i.invited_by AS invited_by_id,
       b.full_name AS invited_by_name, b.email::text AS invited_by_email, d.full_name AS decided_by_name
FROM public.staff_invitations i
LEFT JOIN public.users b ON b.id = i.invited_by
LEFT JOIN public.users d ON d.id = i.decided_by
"""

_CHANGE = """
SELECT r.id, r.action, r.status, r.created_at, r.decided_at, r.decision_note, r.target_id, r.requested_by AS requested_by_id,
       t.full_name AS target_name, t.email::text AS target_email, rb.full_name AS requested_by_name,
       rb.email::text AS requested_by_email, dd.full_name AS decided_by_name
FROM public.admin_change_requests r
JOIN public.users t ON t.id = r.target_id
LEFT JOIN public.users rb ON rb.id = r.requested_by
LEFT JOIN public.users dd ON dd.id = r.decided_by
"""


# ---- invitations -------------------------------------------------------------------------------------------------

def create_invitation(inviter_id, email: str, full_name: str, role: str, code_h, pin_h, hours: int):
    """('ok', {'id'}) | ('taken', None) when the address already has an account | ('open', None) when it already has an
    invitation that is still open. Checked here, BEFORE anything is emailed."""
    with db.transaction() as c:
        if c.execute("SELECT 1 FROM public.users WHERE email = %s", (email,)).fetchone():
            return "taken", None
        c.execute("UPDATE public.staff_invitations SET status = 'expired' "
                  "WHERE email = %s AND status = 'sent' AND code_expires_at < now()", (email,))
        if role == "employer":
            row = c.execute(
                "INSERT INTO public.staff_invitations (email, full_name, role, status, invited_by, code_hash, code_expires_at) "
                "VALUES (%s, %s, 'employer', 'sent', %s, %s, now() + make_interval(hours => %s)) "
                "ON CONFLICT DO NOTHING RETURNING id", (email, full_name, inviter_id, code_h, hours)).fetchone()
        else:
            row = c.execute(
                "INSERT INTO public.staff_invitations (email, full_name, role, status, invited_by, pin_hash) "
                "VALUES (%s, %s, 'admin', 'awaiting_approval', %s, %s) ON CONFLICT DO NOTHING RETURNING id",
                (email, full_name, inviter_id, pin_h)).fetchone()
        if row is None:
            return "open", None
    return "ok", {"id": row["id"]}


def discard_invitation(inv_id) -> None:
    """The email could not be sent: remove the invitation so the address is not blocked by something nobody received."""
    db.run("DELETE FROM public.staff_invitations WHERE id = %s AND status = 'sent' AND accepted_at IS NULL", (inv_id,))


def get_invitation(inv_id):
    return db.one(f"{_INV} WHERE i.id = %s", (inv_id,))


def list_invitations(status: str, limit: int, offset: int):
    p = {"status": status, "limit": limit, "offset": offset}
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM ({_INV}) t WHERE (%(status)s = '' OR t.status = %(status)s)", p).fetchone()["n"]
        rows = c.execute(f"SELECT * FROM ({_INV}) t WHERE (%(status)s = '' OR t.status = %(status)s) "
                         "ORDER BY (t.status IN ('awaiting_approval', 'sent')) DESC, t.created_at DESC "
                         "LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
    return rows, total


def revoke_invitation(inv_id, actor_id):
    """('ok', email) | ('not_found', None) | ('conflict', reason). Only an invitation that is still open."""
    with db.transaction() as c:
        row = c.execute("SELECT email, status, code_expires_at < now() AS stale FROM public.staff_invitations "
                        "WHERE id = %s FOR UPDATE", (inv_id,)).fetchone()
        if not row:
            return "not_found", None
        if row["status"] not in ("awaiting_approval", "sent") or (row["status"] == "sent" and row["stale"]):
            return "conflict", "This invitation is no longer open."
        c.execute("UPDATE public.staff_invitations SET status = 'revoked', decided_by = %s, decided_at = now(), "
                  "code_hash = NULL, pin_hash = NULL WHERE id = %s", (actor_id, inv_id))
    return "ok", row["email"]


def decide_invitation(inv_id, decider_id, approve: bool, note: str, code_h, hours: int):
    """An ADMIN invitation, decided by another administrator.
    ('ok', {'email', 'full_name'}) | ('not_found', None) | ('conflict', reason) | ('same_person', None)."""
    with db.transaction() as c:
        row = c.execute("SELECT email, full_name, role, status, invited_by FROM public.staff_invitations "
                        "WHERE id = %s FOR UPDATE", (inv_id,)).fetchone()
        if not row:
            return "not_found", None
        if row["role"] != "admin" or row["status"] != "awaiting_approval":
            return "conflict", "This invitation is not waiting for approval."
        if row["invited_by"] is not None and str(row["invited_by"]) == str(decider_id):
            return "same_person", None
        if approve:
            c.execute("UPDATE public.staff_invitations SET status = 'sent', code_hash = %s, "
                      "code_expires_at = now() + make_interval(hours => %s), decided_by = %s, decided_at = now(), "
                      "decision_note = %s WHERE id = %s", (code_h, hours, decider_id, note or None, inv_id))
        else:
            c.execute("UPDATE public.staff_invitations SET status = 'rejected', decided_by = %s, decided_at = now(), "
                      "decision_note = %s, pin_hash = NULL WHERE id = %s", (decider_id, note or None, inv_id))
    return "ok", {"email": row["email"], "full_name": row["full_name"]}


def approval_invitations(limit: int = 20):
    """Admin invitations that wait for a decision, then the ones already decided."""
    with db.transaction() as c:
        return c.execute(f"SELECT * FROM ({_INV}) t WHERE t.role = 'admin' AND t.status <> 'revoked' "
                         "ORDER BY (t.status = 'awaiting_approval') DESC, t.created_at DESC LIMIT %s", (limit,)).fetchall()


def accept_invitation(email: str, code: str, pin: str, password_hash: str, username: str, password_check):
    """The invited person sets a password. Wrong code or PIN is counted; too many and the invitation is locked.
    ('ok', {'user_id', 'role'}) | ('invalid', None) | ('taken', None) | ('weak', [errors]).
    password_check(full_name) -> list of problems with the chosen password; it runs only after the code is right,
    so a weak password never burns an attempt and never reveals whether an invitation exists."""
    with db.transaction() as c:
        row = c.execute("SELECT id, role, full_name, code_hash, pin_hash, attempts FROM public.staff_invitations "
                        "WHERE email = %s AND status = 'sent' AND code_expires_at > now() "
                        "ORDER BY created_at DESC LIMIT 1 FOR UPDATE", (email,)).fetchone()
        if not row:
            return "invalid", None
        if row["attempts"] >= config.CODE_MAX_ATTEMPTS:
            c.execute("UPDATE public.staff_invitations SET status = 'locked' WHERE id = %s", (row["id"],))
            return "invalid", None
        ok_code = hmac.compare_digest(row["code_hash"] or "", code_hash(f"invite|{email}", code))
        ok_pin = row["role"] != "admin" or hmac.compare_digest(row["pin_hash"] or "", code_hash(f"invite-pin|{email}", pin))
        if not (ok_code and ok_pin):
            c.execute("UPDATE public.staff_invitations SET attempts = attempts + 1, "
                      "status = CASE WHEN attempts + 1 >= %s THEN 'locked' ELSE status END WHERE id = %s",
                      (config.CODE_MAX_ATTEMPTS, row["id"]))
            return "invalid", None
        problems = password_check(row["full_name"])
        if problems:
            return "weak", problems
        if c.execute("SELECT 1 FROM public.users WHERE email = %s", (email,)).fetchone():
            c.execute("UPDATE public.staff_invitations SET status = 'revoked' WHERE id = %s", (row["id"],))
            return "taken", None
        c.execute("SELECT set_config('app.privileged_role_write', 'on', true)")   # the sanctioned way to create a role
        insert = ("INSERT INTO public.users (email, username, full_name, password_hash, role, is_email_verified, status) "
                  "VALUES (%s, %s, %s, %s, '{}', true, 'active') RETURNING id")
        uid = c.execute(insert.format("admin" if row["role"] == "admin" else "employer"),
                        (email, username, row["full_name"], password_hash)).fetchone()["id"]
        c.execute("UPDATE public.staff_invitations SET status = 'accepted', accepted_user_id = %s, accepted_at = now(), "
                  "code_hash = NULL, pin_hash = NULL WHERE id = %s", (uid, row["id"]))
    return "ok", {"user_id": uid, "role": row["role"]}


# ---- changes to ANOTHER administrator's account ------------------------------------------------------------------

def _valid_change(action: str, status: str, verified: bool):
    """Same state rules as everywhere else. Returns a reason when the change makes no sense, else None."""
    if status == "deleted":
        return "This account is already deleted."
    if action == "deactivate" and status != "active":
        return "Only an active account can be deactivated."
    if action == "activate":
        if status in ("active", "pending"):
            return "This account is not deactivated."
        if not verified:
            return "This account has not verified its email yet."
    return None


def pending_for(ids) -> dict:
    """{target_id: {'id', 'action', 'requested_by'}} for accounts that already have a request waiting."""
    if not ids:
        return {}
    with db.transaction() as c:
        rows = c.execute(f"{_CHANGE} WHERE r.status = 'pending' AND r.target_id = ANY(%s::uuid[])", (sorted(map(str, ids)),)).fetchall()
    return {str(r["target_id"]): {"id": str(r["id"]), "action": r["action"],
                                  "requested_by": r["requested_by_name"] or r["requested_by_email"]} for r in rows}


def create_change(target_id, action: str, requester_id):
    """('ok', {'id', 'email'}) | ('not_found', None) | ('conflict', reason)."""
    with db.transaction() as c:
        t = c.execute("SELECT status::text AS status, role::text AS role, email::text AS email, is_email_verified "
                      "FROM public.users WHERE id = %s AND id <> %s AND role::text = 'admin' FOR UPDATE",
                      (target_id, requester_id)).fetchone()
        if not t:
            return "not_found", None
        why = _valid_change(action, t["status"], t["is_email_verified"])
        if why:
            return "conflict", why
        row = c.execute("INSERT INTO public.admin_change_requests (target_id, action, requested_by) VALUES (%s, %s, %s) "
                        "ON CONFLICT DO NOTHING RETURNING id", (target_id, action, requester_id)).fetchone()
        if row is None:
            return "conflict", "A request for this account is already waiting for approval."
    return "ok", {"id": row["id"], "email": t["email"]}


def list_changes(limit: int = 20):
    """Requests that wait for a decision first, then the latest decided ones."""
    with db.transaction() as c:
        return c.execute(f"{_CHANGE} ORDER BY (r.status = 'pending') DESC, r.created_at DESC LIMIT %s", (limit,)).fetchall()


def decide_change(change_id, decider_id, approve: bool, note: str):
    """('ok', {'action', 'target_id', 'email'}) | ('not_found', None) | ('conflict', reason) | ('same_person', None)
    | ('no_label', None). Approving carries the change out in the same transaction."""
    label = user_admin.disabled_label()
    with db.transaction() as c:
        r = c.execute("SELECT r.action, r.status, r.requested_by, r.target_id, u.email::text AS email "
                      "FROM public.admin_change_requests r JOIN public.users u ON u.id = r.target_id "
                      "WHERE r.id = %s FOR UPDATE OF r", (change_id,)).fetchone()
        if not r:
            return "not_found", None
        if r["status"] != "pending":
            return "conflict", "This request has already been decided."
        decider = str(decider_id)
        if decider == str(r["target_id"]) or (r["requested_by"] is not None and decider == str(r["requested_by"])):
            return "same_person", None
        info = {"action": r["action"], "target_id": r["target_id"], "email": r["email"]}
        if approve:
            t = c.execute("SELECT status::text AS status, is_email_verified FROM public.users WHERE id = %s FOR UPDATE",
                          (r["target_id"],)).fetchone()
            why = _valid_change(r["action"], t["status"], t["is_email_verified"]) if t else "The account no longer exists."
            if not why and r["action"] in ("deactivate", "delete"):
                left = c.execute("SELECT count(*) AS n FROM public.users WHERE role::text = 'admin' "
                                 "AND status::text = 'active' AND id <> %s", (r["target_id"],)).fetchone()["n"]
                if left < 1:
                    why = "At least one active administrator must remain."
            if why:
                c.execute("UPDATE public.admin_change_requests SET status = 'cancelled', decided_by = %s, decided_at = now(), "
                          "decision_note = %s WHERE id = %s", (decider_id, why, change_id))
                return "conflict", why
            if r["action"] == "deactivate":
                if label is None:
                    return "no_label", None
                c.execute("UPDATE public.users SET status = %s::public.account_status WHERE id = %s", (label, r["target_id"]))
            elif r["action"] == "activate":
                c.execute("UPDATE public.users SET status = 'active', failed_login_count = 0, locked_until = NULL "
                          "WHERE id = %s", (r["target_id"],))
            else:
                c.execute("UPDATE public.users SET status = 'deleted' WHERE id = %s", (r["target_id"],))
        c.execute("UPDATE public.admin_change_requests SET status = %s, decided_by = %s, decided_at = now(), "
                  "decision_note = %s WHERE id = %s", ("approved" if approve else "rejected", decider_id, note or None, change_id))
    return "ok", info
