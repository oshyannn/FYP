"""Feedback threads (Model layer). A thread is one row with parent_id NULL; replies are rows pointing at it.
Users only ever reach their own threads; staff (employer / admin) reach all of them."""
from __future__ import annotations

from web import db

_LIST_SELECT = """
SELECT f.id, f.category::text AS category, f.subject, f.status::text AS status, f.created_at, f.updated_at,
       f.history_id IS NOT NULL AS has_scan, u.full_name AS author_name, u.email::text AS author_email,
       (SELECT count(*) FROM public.feedback r WHERE r.parent_id = f.id) AS reply_count,
       (SELECT max(r.created_at) FROM public.feedback r WHERE r.parent_id = f.id) AS last_reply_at
FROM public.feedback f JOIN public.users u ON u.id = f.user_id
"""
EDITABLE = ("open", "in_progress")


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def list_page(*, owner_id=None, status: str, category: str, q: str, limit: int, offset: int):
    """owner_id=None lists every thread (staff)."""
    p = {"owner": owner_id, "status": status, "category": category, "q": q, "like": _like(q),
         "limit": limit, "offset": offset}
    where = """f.parent_id IS NULL
        AND (%(owner)s::uuid IS NULL OR f.user_id = %(owner)s::uuid)
        AND (%(status)s = '' OR f.status = NULLIF(%(status)s, '')::public.feedback_status)
        AND (%(category)s = '' OR f.category = NULLIF(%(category)s, '')::public.feedback_category)
        AND (%(q)s = '' OR f.subject ILIKE %(like)s ESCAPE '\\' OR f.message ILIKE %(like)s ESCAPE '\\'
             OR u.full_name ILIKE %(like)s ESCAPE '\\' OR u.email::text ILIKE %(like)s ESCAPE '\\')"""
    with db.transaction() as c:
        total = c.execute("SELECT count(*) AS n FROM public.feedback f JOIN public.users u ON u.id = f.user_id "
                          f"WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"{_LIST_SELECT} WHERE {where} ORDER BY greatest(f.created_at, coalesce("
                         "(SELECT max(r.created_at) FROM public.feedback r WHERE r.parent_id = f.id), f.created_at)) DESC "
                         "LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
        counts = {r["s"]: r["n"] for r in c.execute(
            "SELECT status::text AS s, count(*) AS n FROM public.feedback WHERE parent_id IS NULL "
            "AND (%s::uuid IS NULL OR user_id = %s::uuid) GROUP BY 1", (owner_id, owner_id)).fetchall()}
    return rows, total, {k: counts.get(k, 0) for k in ("open", "in_progress", "resolved", "closed")}


def get_thread(fid, owner_id=None):
    """(thread, replies) or (None, []). The attached scan result comes along with its analysis."""
    with db.transaction() as c:
        t = c.execute(
            """SELECT f.id, f.category::text AS category, f.subject, f.message, f.status::text AS status,
                      f.created_at, f.updated_at, f.resolved_at, rb.full_name AS resolved_by_name,
                      u.full_name AS author_name, u.email::text AS author_email,
                      h.id AS scan_id, h.url AS scan_url, h.domain AS scan_domain,
                      h.risk_level::text AS scan_level, h.risk_score AS scan_score, h.scanned_at AS scan_at,
                      h.analysis AS scan_analysis
               FROM public.feedback f
               JOIN public.users u ON u.id = f.user_id
               LEFT JOIN public.users rb ON rb.id = f.resolved_by
               LEFT JOIN public.detection_history h ON h.id = f.history_id
               WHERE f.id = %s AND f.parent_id IS NULL AND (%s::uuid IS NULL OR f.user_id = %s::uuid)""",
            (fid, owner_id, owner_id)).fetchone()
        if not t:
            return None, []
        replies = c.execute(
            "SELECT r.id, r.message, r.created_at, u.full_name AS author_name, u.role::text AS author_role "
            "FROM public.feedback r JOIN public.users u ON u.id = r.user_id "
            "WHERE r.parent_id = %s ORDER BY r.created_at, r.id", (fid,)).fetchall()
    return t, replies


def _own_scan(c, user_id, history_id) -> bool:
    return c.execute("SELECT 1 FROM public.detection_history WHERE id = %s AND user_id = %s AND is_deleted = false",
                     (history_id, user_id)).fetchone() is not None


def create(user_id, category: str, subject: str, message: str, history_id):
    """Returns the new id, or 'bad_scan' when the attached scan is not the caller's own."""
    with db.transaction() as c:
        if history_id and not _own_scan(c, user_id, history_id):
            return "bad_scan"
        return c.execute(
            "INSERT INTO public.feedback (user_id, history_id, category, subject, message) "
            "VALUES (%s, %s, %s::public.feedback_category, %s, %s) RETURNING id",
            (user_id, history_id, category, subject, message)).fetchone()["id"]


def update(fid, owner_id, changes: dict) -> str:
    """changes may hold category, subject, message, history_id (None detaches). 'ok' | 'not_found' | 'locked' | 'bad_scan'."""
    with db.transaction() as c:
        row = c.execute("SELECT status::text AS status FROM public.feedback "
                        "WHERE id = %s AND user_id = %s AND parent_id IS NULL FOR UPDATE", (fid, owner_id)).fetchone()
        if not row:
            return "not_found"
        if row["status"] not in EDITABLE:
            return "locked"
        if changes.get("history_id") and not _own_scan(c, owner_id, changes["history_id"]):
            return "bad_scan"
        sets, params = [], {"id": fid}
        for col, cast in (("category", "::public.feedback_category"), ("subject", ""), ("message", ""), ("history_id", "")):
            if col in changes:
                sets.append(f"{col} = %({col})s{cast}")
                params[col] = changes[col]
        if sets:
            c.execute(f"UPDATE public.feedback SET {', '.join(sets)} WHERE id = %(id)s", params)
    return "ok"


def add_reply(fid, author_id, message: str, *, staff: bool, owner_id=None, new_status: str = "") -> str:
    """'ok' | 'not_found' | 'closed'. A staff reply moves an open thread to in_progress (or to the status chosen);
    a user's follow-up on a resolved thread reopens it."""
    with db.transaction() as c:
        t = c.execute("SELECT status::text AS status, subject, category::text AS category FROM public.feedback "
                      "WHERE id = %s AND parent_id IS NULL AND (%s::uuid IS NULL OR user_id = %s::uuid) FOR UPDATE",
                      (fid, owner_id, owner_id)).fetchone()
        if not t:
            return "not_found"
        if t["status"] == "closed":
            return "closed"
        c.execute("INSERT INTO public.feedback (parent_id, user_id, category, subject, message) "
                  "VALUES (%s, %s, %s::public.feedback_category, %s, %s)",
                  (fid, author_id, t["category"], ("Re: " + t["subject"])[:200], message))
        if staff:
            target = new_status or ("in_progress" if t["status"] == "open" else t["status"])
        else:
            target = "open" if t["status"] == "resolved" else t["status"]
        if target != t["status"]:
            _set_status(c, fid, target, author_id)
    return "ok"


def _set_status(c, fid, status: str, staff_id) -> None:
    terminal = status in ("resolved", "closed")
    c.execute("UPDATE public.feedback SET status = %(s)s::public.feedback_status, "
              "resolved_by = CASE WHEN %(t)s THEN COALESCE(resolved_by, %(by)s::uuid) ELSE NULL END, "
              "resolved_at = CASE WHEN %(t)s THEN COALESCE(resolved_at, now()) ELSE NULL END WHERE id = %(id)s",
              {"s": status, "t": terminal, "by": staff_id, "id": fid})


def set_status(fid, staff_id, status: str) -> str:
    """'ok' | 'not_found' | 'closed' (a closed thread stays closed)."""
    with db.transaction() as c:
        t = c.execute("SELECT status::text AS status FROM public.feedback WHERE id = %s AND parent_id IS NULL FOR UPDATE",
                      (fid,)).fetchone()
        if not t:
            return "not_found"
        if t["status"] == "closed":
            return "closed"
        if t["status"] != status:
            _set_status(c, fid, status, staff_id)
    return "ok"
