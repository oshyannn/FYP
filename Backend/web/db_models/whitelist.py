"""Trusted sites (Model layer).

whitelist_entries  : trusted addresses. scope 'user' = one person's own list, scope 'global' = set by an administrator.
                     path_prefix NULL = the whole website; otherwise only that page path and the pages below it.
whitelist_requests : a user asks for an address to be trusted; an employer or administrator approves or rejects it.
Approving a request adds the address to the REQUESTER's own list only (never to the global one).

check_request() is the single place that decides whether a new address already exists in ANY list the detector uses
(trusted entries, manual whitelist, top sites, trusted suffixes, blocked lists, threat list, pending requests).
"""
from __future__ import annotations

from urllib.parse import urlsplit

from web import db

_ENTRY = ("SELECT e.id, e.domain, e.path_prefix, e.scope, e.created_at, e.added_by, u.full_name AS added_by_name, "
          "u.email::text AS added_by_email "
          "FROM public.whitelist_entries e LEFT JOIN public.users u ON u.id = e.added_by")

_REQUEST = """
SELECT r.id, r.domain, r.path_prefix, r.reason, r.risk_score, r.risk_level, r.status, r.review_note, r.created_at, r.reviewed_at,
       u.email::text AS requester_email, u.full_name AS requester_name, rv.full_name AS reviewed_by_name
FROM public.whitelist_requests r
JOIN public.users u ON u.id = r.user_id
LEFT JOIN public.users rv ON rv.id = r.reviewed_by
"""

_TOP_N = "coalesce((SELECT NULLIF(value, '')::int FROM public.detection_settings WHERE key = 'whitelist_top_n'), 10000)"
_BLOCK_TYPES = ("blacklist", "adblock_block", "adult_manual")
_ALLOW_TYPES = ("whitelist", "trusted_prefixes", "adblock_allow", "trusted_suffixes")


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


# ---- address helpers (pure functions, no database) ---------------------------------------------------------------

def parents_of(host: str) -> list[str]:
    """'a.b.example.com' -> ['a.b.example.com', 'b.example.com', 'example.com'].
    The bare top-level label (com, my, ...) is never a parent, so one entry can never trust a whole country."""
    parts = host.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)]


def path_prefixes(path: str) -> list[str]:
    """'/shop/item' -> ['', '/shop', '/shop/item']. '' means the whole site."""
    out, acc = [""], ""
    for seg in (p for p in path.split("/") if p):
        acc += "/" + seg
        out.append(acc)
    return out


def covers(scope_path: str | None, path: str) -> bool:
    """Does a rule for scope_path cover the address path? A NULL/'' rule covers the whole site.
    Matches on path-segment boundaries: '/shop' covers '/shop/x' but not '/shopping'."""
    if not scope_path:
        return True
    return path == scope_path or path.startswith(scope_path + "/")


def _url_path(url: str) -> str:
    """'https://a.com/shop/' -> '/shop'. Empty string when the address has no page path."""
    p = urlsplit(url if "://" in url else "https://" + url).path or ""
    segs = [seg for seg in p.split("/") if seg]
    return "/" + "/".join(segs) if segs else ""


# ---- trusted domains -------------------------------------------------------------------------------------------

def list_entries(scope: str, user_id, limit: int, offset: int):
    """scope 'global' = the administrator's list, 'user' = this person's own list."""
    where = "e.scope = 'global'" if scope == "global" else "e.scope = 'user' AND e.user_id = %(uid)s"
    p = {"uid": user_id, "limit": limit, "offset": offset}
    with db.transaction() as c:
        total = c.execute(f"SELECT count(*) AS n FROM public.whitelist_entries e WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"{_ENTRY} WHERE {where} ORDER BY e.created_at DESC, e.domain, e.path_prefix "
                         "LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
    return rows, total


def check_request(user_id, host: str, path: str) -> dict:
    """Is this address already covered by anything? Returns {'conflict': message or None, 'warnings': [messages]}.

    A conflict blocks the request. A warning does not: it tells the reviewer that narrower entries exist inside
    a whole-site request, which the new rule would also cover."""
    hosts = parents_of(host)
    keys = [h + p for h in hosts for p in path_prefixes(path)]    # every 'host/path' that could cover this address
    out = {"conflict": None, "warnings": []}

    def block(msg: str) -> None:
        if out["conflict"] is None:
            out["conflict"] = msg

    with db.transaction() as c:
        entries = c.execute(
            "SELECT scope, domain, path_prefix FROM public.whitelist_entries "
            "WHERE domain = ANY(%(hosts)s) AND (scope = 'global' OR (scope = 'user' AND user_id = %(uid)s))",
            {"hosts": hosts, "uid": user_id}).fetchall()
        pending = c.execute(
            "SELECT domain, path_prefix FROM public.whitelist_requests "
            "WHERE user_id = %(uid)s AND status = 'pending' AND domain = ANY(%(hosts)s)",
            {"hosts": hosts, "uid": user_id}).fetchall()
        lists = c.execute(
            "SELECT list_type::text AS lt, value FROM public.detection_lists WHERE is_active AND ("
            "  value = ANY(%(keys)s) OR "
            "  (list_type = 'trusted_suffixes' AND (%(host)s = ltrim(value, '.') "
            "     OR right(%(host)s, char_length(ltrim(value, '.')) + 1) = '.' || ltrim(value, '.')))"
            ") AND list_type::text = ANY(%(types)s)",
            {"keys": keys, "host": host, "types": list(_ALLOW_TYPES + _BLOCK_TYPES + ("shared_hosts",))}).fetchall()
        threats = c.execute(
            "SELECT url, normalized_url FROM public.global_urls "
            "WHERE status = 'active' AND risk_level IN ('suspicious', 'malicious') AND domain = ANY(%(hosts)s)",
            {"hosts": hosts}).fetchall()
        top = c.execute(
            f"SELECT t.domain FROM public.trusted_top_sites t WHERE t.domain = ANY(%(hosts)s) AND t.rank <= {_TOP_N} "
            "AND NOT EXISTS (SELECT 1 FROM public.detection_lists d "
            "                WHERE d.list_type = 'not_trusted' AND d.is_active AND d.value = t.domain)",
            {"hosts": hosts}).fetchall()

    # 1. trusted entries (global or this person's)
    for e in entries:
        pp = e["path_prefix"]
        if covers(pp, path):
            who = "already trusted for every user" if e["scope"] == "global" else "already on your trusted list"
            block(f"This address is {who} ({e['domain']}{pp or ''}).")
        elif pp and covers(path, pp):
            out["warnings"].append(f"A narrower trusted entry exists inside this request: {e['domain']}{pp}.")

    # 2. the same address already waiting for review
    for p in pending:
        if covers(p["path_prefix"], path):
            block("You already asked for this address. It is waiting for review.")

    # 3. detector lists: allow lists, suffixes, block lists, public hosting platforms
    for row in lists:
        lt, value = row["lt"], row["value"]
        if lt in _ALLOW_TYPES:
            block(f"This address is already on the SafeBrowse trusted list ({value}).")
        elif lt in _BLOCK_TYPES:
            block(f"This address is on the blocked list ({value}), so it cannot be trusted.")
        elif lt == "shared_hosts" and value in hosts and not path:
            block("This is a public hosting platform. Request the exact page address instead, for example "
                  f"{host}/your-page.")

    # 4. known threats: a threat under the requested scope means the scope cannot be trusted
    for t in threats:
        tpath = _url_path(t["normalized_url"] or t["url"])
        if covers(path, tpath):
            block("A known threat is listed on this site, so it cannot be trusted. Request a specific safe page instead.")
            break

    # 5. top sites are already trusted by the detector
    if top:
        block(f"This address is already trusted as a top site ({top[0]['domain']}).")

    return out


def add_global(admin_id, domain: str, path: str):
    """Adds an address to the global list. Returns {'id', 'created_at'}, or None when it was already there."""
    return db.one("INSERT INTO public.whitelist_entries (scope, domain, path_prefix, added_by) "
                  "VALUES ('global', %s, %s, %s) ON CONFLICT DO NOTHING RETURNING id, created_at",
                  (domain, path or None, admin_id))


def trusted_scope(user_id, host: str):
    """'global' or 'user' when this host (or a parent domain of it) is trusted for the whole site, else None.
    Kept for the scanner: it only looks at whole-site entries."""
    row = db.one(
        "SELECT scope FROM public.whitelist_entries "
        "WHERE path_prefix IS NULL AND (scope = 'global' OR (scope = 'user' AND user_id = %(uid)s)) "
        "AND domain = ANY(%(hosts)s) ORDER BY (scope = 'global') DESC LIMIT 1",
        {"uid": user_id, "hosts": parents_of(host)})
    return row["scope"] if row else None


def remove(entry_id, scope: str, user_id) -> bool:
    """Deletes one entry. A user can only delete from their own list, an administrator only from the global one."""
    if scope == "global":
        row = db.one("DELETE FROM public.whitelist_entries WHERE id = %s AND scope = 'global' RETURNING id", (entry_id,))
    else:
        row = db.one("DELETE FROM public.whitelist_entries WHERE id = %s AND scope = 'user' AND user_id = %s "
                     "RETURNING id", (entry_id, user_id))
    return row is not None


# ---- requests --------------------------------------------------------------------------------------------------

def create_request(user_id, domain: str, path: str, reason, risk_score, risk_level: str):
    """Returns the new row, or None when this person already has a pending request for the same address
    (the unique index whitelist_requests_one_pending enforces it, so two clicks cannot create two rows)."""
    return db.one("INSERT INTO public.whitelist_requests (user_id, domain, path_prefix, reason, risk_score, risk_level) "
                  "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING "
                  "RETURNING id, domain, path_prefix, reason, risk_score, risk_level, status, review_note, created_at, reviewed_at",
                  (user_id, domain, path or None, reason, risk_score, risk_level))


def my_requests(user_id, limit: int = 20):
    """Pending requests, and rejected ones from the last 30 days, so the person can see what happened."""
    with db.transaction() as c:
        return c.execute(
            "SELECT id, domain, path_prefix, reason, risk_score, risk_level, status, review_note, created_at, reviewed_at "
            "FROM public.whitelist_requests WHERE user_id = %s AND (status = 'pending' "
            "OR (status = 'rejected' AND reviewed_at > now() - interval '30 days')) "
            "ORDER BY created_at DESC LIMIT %s", (user_id, limit)).fetchall()


def list_requests(status: str, q: str, limit: int, offset: int):
    p = {"status": status, "q": q, "like": _like(q), "limit": limit, "offset": offset}
    where = """(%(status)s = '' OR r.status = %(status)s)
               AND (%(q)s = '' OR r.domain ILIKE %(like)s ESCAPE '\\' OR u.email::text ILIKE %(like)s ESCAPE '\\')"""
    with db.transaction() as c:
        total = c.execute("SELECT count(*) AS n FROM public.whitelist_requests r "
                          f"JOIN public.users u ON u.id = r.user_id WHERE {where}", p).fetchone()["n"]
        rows = c.execute(f"{_REQUEST} WHERE {where} ORDER BY (r.status = 'pending') DESC, r.created_at DESC "
                         "LIMIT %(limit)s OFFSET %(offset)s", p).fetchall()
        counts = {r["s"]: r["n"] for r in c.execute(
            "SELECT status AS s, count(*) AS n FROM public.whitelist_requests GROUP BY 1").fetchall()}
    return rows, total, {"pending": counts.get("pending", 0), "approved": counts.get("approved", 0),
                         "rejected": counts.get("rejected", 0)}


def get_request(req_id):
    return db.one(f"{_REQUEST} WHERE r.id = %s", (req_id,))


def review_request(req_id, reviewer_id, decision: str, note: str) -> str:
    """decision: 'approve' | 'reject'. Only a pending request can be reviewed.
    Approving adds the address to the GLOBAL trusted list via public.review_whitelist_request().
    Returns 'ok', 'not_found' or 'conflict' (already reviewed)."""
    row = db.one(
        "SELECT public.review_whitelist_request(%s, %s, %s, %s) AS outcome",
        (req_id, reviewer_id, decision, note or ""),
    )
    return row["outcome"] if row else "not_found"


def update_approved_request(req_id, host: str, path: str) -> str:
    """Updates domain/path_prefix on an approved whitelist request and its global whitelist_entries row."""
    with db.transaction() as c:
        row = c.execute("SELECT status FROM public.whitelist_requests WHERE id = %s FOR UPDATE", (req_id,)).fetchone()
        if not row:
            return "not_found"
        if row["status"] != "approved":
            return "conflict"
        dup = c.execute(
            "SELECT 1 FROM public.whitelist_entries WHERE scope = 'global' AND domain = %s "
            "AND coalesce(path_prefix, '') = %s AND (request_id IS NULL OR request_id <> %s)",
            (host, path, req_id),
        ).fetchone()
        if dup:
            return "duplicate"
        c.execute(
            "UPDATE public.whitelist_requests SET domain = %s, path_prefix = %s WHERE id = %s",
            (host, path or None, req_id),
        )
        c.execute(
            "UPDATE public.whitelist_entries SET domain = %s, path_prefix = %s WHERE request_id = %s",
            (host, path or None, req_id),
        )
    return "ok"


def delete_approved_request(req_id) -> str:
    """Removes an approved whitelist request and its corresponding global whitelist_entries row."""
    with db.transaction() as c:
        row = c.execute("SELECT status FROM public.whitelist_requests WHERE id = %s FOR UPDATE", (req_id,)).fetchone()
        if not row:
            return "not_found"
        if row["status"] != "approved":
            return "conflict"
        c.execute("DELETE FROM public.whitelist_entries WHERE request_id = %s", (req_id,))
        c.execute("DELETE FROM public.whitelist_requests WHERE id = %s", (req_id,))
    return "ok"
