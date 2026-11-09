"""Read-only view of the lists the detector really uses (Model layer), for every signed-in person.

trusted    Tranco top sites (rank <= whitelist_top_n, minus 'not_trusted') + the manual whitelist
blocked    manual blacklist + the administrator-approved Global Threat List (active entries)
feed       exact phishing / malware addresses from OpenPhish, URLhaus and PhishTank
adult      adult-site domains (about a million: only searchable)
shared     public hosting platforms that are never trusted by domain
"""
from __future__ import annotations

from web import db

KINDS = ("trusted", "blocked", "feed", "adult", "shared")
ADULT_MIN_SEARCH = 3
_CAP = 10001                      # a search that matches more than this is shown as "10,000+"

_TOP_N = "coalesce((SELECT NULLIF(value, '')::int FROM public.detection_settings WHERE key = 'whitelist_top_n'), 10000)"


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def summary() -> dict:
    with db.transaction() as c:
        one = lambda sql: c.execute(sql).fetchone()["n"]          # noqa: E731
        top_n = one(f"SELECT {_TOP_N} AS n")
        manual = one("SELECT count(*) AS n FROM public.detection_lists WHERE list_type = 'whitelist' AND is_active")
        not_trusted = one("SELECT count(*) AS n FROM public.detection_lists WHERE list_type = 'not_trusted' AND is_active")
        tranco = one(f"SELECT count(*) AS n FROM public.trusted_top_sites t WHERE t.rank <= {_TOP_N} "
                     "AND t.domain NOT IN (SELECT value FROM public.detection_lists WHERE list_type = 'not_trusted' AND is_active)")
        manual_bl = one("SELECT count(*) AS n FROM public.detection_lists WHERE list_type = 'blacklist' AND is_active")
        admin_bl = one("SELECT count(*) AS n FROM public.global_urls WHERE status = 'active' AND risk_level IN ('suspicious', 'malicious')")
        shared = one("SELECT count(*) AS n FROM public.detection_lists WHERE list_type = 'shared_hosts' AND is_active")
        adult_manual = one("SELECT count(*) AS n FROM public.detection_lists WHERE list_type = 'adult_manual' AND is_active")
        sync = {r["name"]: r for r in c.execute("SELECT name, row_count, synced_at FROM public.list_sync_status").fetchall()}

    def big(name):
        r = sync.get(name)
        return {"count": int(r["row_count"]) if r else 0, "synced_at": r["synced_at"].isoformat() if r else None}
    adult = big("adult_domains")
    adult["count"] += adult_manual
    return {
        "trusted": {"count": tranco + manual, "top_sites": tranco, "manual": manual, "not_trusted": not_trusted, "top_n": top_n,
                    "synced_at": big("trusted_top_sites")["synced_at"]},
        "blocked": {"count": manual_bl + admin_bl, "manual": manual_bl, "admin_approved": admin_bl},
        "feed": big("threat_feed_urls"),
        "adult": adult,
        "shared": {"count": shared},
    }


def _page(c, sql_rows: str, sql_count: str, p: dict):
    total = c.execute(sql_count, p).fetchone()["n"]
    return c.execute(sql_rows, p).fetchall(), total


def items(kind: str, q: str, limit: int, offset: int):
    """(rows, total, capped). Every row: item, source, detail, level, score, added_at."""
    p = {"q": q, "like": _like(q), "limit": limit, "offset": offset, "cap": _CAP}
    with db.transaction() as c:
        if kind == "trusted":
            base = f"""
                SELECT value AS item, 'Manual whitelist' AS source, NULL::text AS detail, created_at AS added_at, 0 AS ord, 0 AS rank
                  FROM public.detection_lists WHERE list_type = 'whitelist' AND is_active
                UNION ALL
                SELECT t.domain, 'Top sites (Tranco)', 'Rank ' || t.rank, NULL, 1, t.rank
                  FROM public.trusted_top_sites t
                 WHERE t.rank <= {_TOP_N}
                   AND t.domain NOT IN (SELECT value FROM public.detection_lists WHERE list_type = 'not_trusted' AND is_active)"""
            where = "(%(q)s = '' OR item ILIKE %(like)s ESCAPE '\\')"
            rows, total = _page(c,
                f"SELECT item, source, detail, NULL::text AS level, NULL::numeric AS score, added_at FROM ({base}) x WHERE {where} "
                "ORDER BY ord, rank, item LIMIT %(limit)s OFFSET %(offset)s",
                f"SELECT count(*) AS n FROM ({base}) x WHERE {where}", p)
            return rows, total, False
        if kind == "blocked":
            base = """
                SELECT value AS item, 'Manual blacklist' AS source, 'Whole domain' AS detail, 'malicious' AS level,
                       100::numeric AS score, created_at AS added_at
                  FROM public.detection_lists WHERE list_type = 'blacklist' AND is_active
                UNION ALL
                SELECT url, 'Administrator-approved threat', threat_type::text, risk_level::text, risk_score, last_verified_at
                  FROM public.global_urls WHERE status = 'active' AND risk_level IN ('suspicious', 'malicious')"""
            where = "(%(q)s = '' OR item ILIKE %(like)s ESCAPE '\\')"
            rows, total = _page(c,
                f"SELECT item, source, detail, level, score, added_at FROM ({base}) x WHERE {where} "
                "ORDER BY added_at DESC NULLS LAST, item LIMIT %(limit)s OFFSET %(offset)s",
                f"SELECT count(*) AS n FROM ({base}) x WHERE {where}", p)
            return rows, total, False
        if kind == "shared":
            where = "list_type = 'shared_hosts' AND is_active AND (%(q)s = '' OR value ILIKE %(like)s ESCAPE '\\')"
            rows, total = _page(c,
                f"SELECT value AS item, 'Public hosting platform' AS source, NULL::text AS detail, NULL::text AS level, "
                f"NULL::numeric AS score, created_at AS added_at FROM public.detection_lists WHERE {where} "
                "ORDER BY value LIMIT %(limit)s OFFSET %(offset)s",
                f"SELECT count(*) AS n FROM public.detection_lists WHERE {where}", p)
            return rows, total, False
        if kind == "feed":
            where = "(%(q)s = '' OR url ILIKE %(like)s ESCAPE '\\')"
            rows, total = _page(c,
                f"SELECT url AS item, 'OpenPhish / URLhaus / PhishTank feed' AS source, NULL::text AS detail, 'malicious' AS level, "
                f"100::numeric AS score, NULL::timestamptz AS added_at FROM public.threat_feed_urls WHERE {where} "
                "ORDER BY url LIMIT %(limit)s OFFSET %(offset)s",
                f"SELECT count(*) AS n FROM (SELECT 1 FROM public.threat_feed_urls WHERE {where} LIMIT %(cap)s) x", p)
            return rows, total, total >= _CAP
        # adult: only searchable
        where = "domain ILIKE %(like)s ESCAPE '\\'"
        rows, total = _page(c,
            f"SELECT domain AS item, 'Adult-site list' AS source, NULL::text AS detail, NULL::text AS level, NULL::numeric AS score, "
            f"NULL::timestamptz AS added_at FROM public.adult_domains WHERE {where} "
            "ORDER BY domain LIMIT %(limit)s OFFSET %(offset)s",
            f"SELECT count(*) AS n FROM (SELECT 1 FROM public.adult_domains WHERE {where} LIMIT %(cap)s) x", p)
        return rows, total, total >= _CAP


def check(domain: str) -> dict:
    """Which lists a domain (or a parent domain of it) is on."""
    parents = []
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        parents.append(".".join(parts[i:]))
    p = {"d": domain, "parents": parents, "like": _like(domain)}
    with db.transaction() as c:
        top = c.execute(f"SELECT t.rank, {_TOP_N} AS top_n FROM public.trusted_top_sites t WHERE t.domain = ANY(%(parents)s) "
                        "ORDER BY t.rank LIMIT 1", p).fetchone()
        top_n = (top or {}).get("top_n") or c.execute(f"SELECT {_TOP_N} AS n").fetchone()["n"]
        managed = c.execute("SELECT list_type::text AS list_type FROM public.detection_lists "
                            "WHERE is_active AND value = ANY(%(parents)s) "
                            "AND list_type IN ('whitelist', 'not_trusted', 'blacklist', 'adult_manual', 'shared_hosts')", p).fetchall()
        threats = c.execute("SELECT url, risk_level::text AS level FROM public.global_urls WHERE status = 'active' "
                            "AND risk_level IN ('suspicious', 'malicious') AND domain = ANY(%(parents)s) LIMIT 5", p).fetchall()
        adult = c.execute("SELECT 1 AS n FROM public.adult_domains WHERE domain = ANY(%(parents)s) LIMIT 1", p).fetchone()
        feed = c.execute("SELECT url FROM public.threat_feed_urls WHERE url ILIKE %(like)s ESCAPE '\\' LIMIT 5", p).fetchall()
    in_lists = sorted({m["list_type"] for m in managed})
    rank = int(top["rank"]) if top else None
    tranco = rank is not None and rank <= int(top_n) and "not_trusted" not in in_lists
    return {"domain": domain, "tranco_rank": rank, "top_n": int(top_n), "trusted_top_site": tranco, "managed_lists": in_lists,
            "admin_threats": [{"url": t["url"], "level": t["level"]} for t in threats],
            "adult": adult is not None, "feed_matches": [f["url"] for f in feed]}
