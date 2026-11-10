"""Password reset help requests and one-time reset tickets (Model layer).

password_reset_requests  someone asks an approver to send them a reset code. Nothing is emailed until it is approved.
                         Who may approve is decided in controllers/password_reset.py, not here.
reset tickets            after the 6-digit code is right, the person gets a short-lived ticket. It lets them set a new
                         password in a second step. Single use; stored only as an HMAC, in auth_tokens.
"""
from __future__ import annotations

from web import db
from web.security import code_hash, new_token

TICKET_MINUTES = 10

_LIST = """
SELECT r.id, r.status, r.created_at, r.decided_at, r.decision_note,
       t.id AS user_id, t.role::text AS role, t.full_name, t.email::text AS email,
       d.full_name AS decided_by_name
FROM public.password_reset_requests r
JOIN public.users t ON t.id = r.user_id
LEFT JOIN public.users d ON d.id = r.decided_by
"""


def create_request(user_id):
    """The new request, or None when this account already has one waiting."""
    return db.one("INSERT INTO public.password_reset_requests (user_id) VALUES (%s) "
                  "ON CONFLICT (user_id) WHERE status = 'pending' DO NOTHING RETURNING id", (user_id,))


def get(req_id):
    return db.one(f"{_LIST} WHERE r.id = %s", (req_id,))


def list_pending(approver_id, approver_role: str, limit: int = 50):
    """Pending requests this approver may decide, oldest first.
    employer      : only user accounts.
    administrator : user and employer accounts, and administrator accounts other than their own."""
    if approver_role == "employer":
        where = "r.status = 'pending' AND t.role::text = 'user'"
    else:
        where = ("r.status = 'pending' AND (t.role::text IN ('user', 'employer') "
                 "OR (t.role::text = 'admin' AND t.id <> %(me)s))")
    with db.transaction() as c:
        return c.execute(f"{_LIST} WHERE {where} ORDER BY r.created_at LIMIT %(limit)s",
                         {"me": str(approver_id), "limit": limit}).fetchall()


def mark_decided(req_id, approver_id, status: str, note: str) -> bool:
    """True when the request was still pending and is now approved or rejected."""
    row = db.one("UPDATE public.password_reset_requests SET status = %s, decided_by = %s, decided_at = now(), "
                 "decision_note = %s WHERE id = %s AND status = 'pending' RETURNING id",
                 (status, approver_id, note or None, req_id))
    return row is not None


def issue_ticket(user_id) -> str:
    token = new_token()
    db.run("INSERT INTO public.auth_tokens (user_id, token_hash, purpose, expires_at) "
           "VALUES (%s, %s, 'signup_handoff'::public.token_purpose, now() + %s * interval '1 minute')",
           (user_id, code_hash("reset-ticket", token), TICKET_MINUTES))
    return token


def consume_ticket(user_id, token: str) -> bool:
    """Uses the ticket up. True only for the right user, unexpired, and unused."""
    row = db.one("UPDATE public.auth_tokens SET consumed_at = now() WHERE user_id = %s AND token_hash = %s "
                 "AND purpose = 'signup_handoff'::public.token_purpose AND consumed_at IS NULL "
                 "AND expires_at > now() RETURNING id", (user_id, code_hash("reset-ticket", token)))
    return row is not None
