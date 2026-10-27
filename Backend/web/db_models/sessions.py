"""Server-side sessions behind bearer tokens. Only the SHA-256 hash of the token is stored."""
from __future__ import annotations

import db


def create(user_id, portal: str, token_hash: str, hours: int, idle_minutes: int,
           ip: str | None, user_agent: str, label: str | None = None) -> None:
    db.run("INSERT INTO public.sessions (user_id, portal, token_hash, ip_address, user_agent, label, idle_minutes, expires_at) "
           "VALUES (%s, %s::public.session_portal, %s, %s::inet, %s, %s, %s, now() + %s * interval '1 hour')",
           (user_id, portal, token_hash, ip, user_agent, label, idle_minutes, hours))


def get_active(token_hash: str):
    return db.one("""
        SELECT s.id AS sid, s.portal::text AS portal,
               u.id, u.email::text AS email, u.full_name, u.username,
               u.role::text AS role, u.status::text AS status, u.is_email_verified
        FROM public.sessions s JOIN public.users u ON u.id = s.user_id
        WHERE s.token_hash = %s AND s.revoked_at IS NULL AND s.expires_at > now()
          AND s.last_seen_at > now() - s.idle_minutes * interval '1 minute'
        """, (token_hash,))


def touch(sid) -> None:
    db.run("UPDATE public.sessions SET last_seen_at = now() "
           "WHERE id = %s AND last_seen_at < now() - interval '1 minute'", (sid,))


def revoke(sid) -> None:
    db.run("UPDATE public.sessions SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL", (sid,))


def revoke_all_for_user(user_id, except_sid=None) -> None:
    db.run("UPDATE public.sessions SET revoked_at = now() "
           "WHERE user_id = %s AND revoked_at IS NULL AND (%s::uuid IS NULL OR id <> %s::uuid)",
           (user_id, except_sid, except_sid))


def list_extensions(user_id):
    with db.transaction() as c:
        return c.execute("SELECT id, label, created_at, last_seen_at FROM public.sessions "
                         "WHERE user_id = %s AND portal = 'extension' AND revoked_at IS NULL "
                         "AND expires_at > now() ORDER BY created_at DESC", (user_id,)).fetchall()


def revoke_extension(sid, user_id) -> bool:
    row = db.one("UPDATE public.sessions SET revoked_at = now() "
                 "WHERE id = %s AND user_id = %s AND portal = 'extension' AND revoked_at IS NULL RETURNING id",
                 (sid, user_id))
    return row is not None
