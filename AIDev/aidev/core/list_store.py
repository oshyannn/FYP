"""
Detector lists from Supabase, with safe fallbacks.        Put this file in  AIDev/aidev/core/

    from aidev.core import list_store as store
    WHITELIST   = set(store.small("whitelist", LISTS / "whitelist.txt"))
    ADULT       = set(store.adult_domains())
    TOP_SITES   = store.top_sites()          # ordered, rank 1 first
    FEEDS       = store.feed_urls()
    N           = store.setting("whitelist_top_n", 10000)

Where each list comes from, in this order:
  small lists (detection_lists)   Supabase  ->  AIDev/lists/<name>.txt
  big lists (Tranco, feeds, adult) local cache (if it is still the version Supabase has)  ->  Supabase  ->  stale cache  ->  AIDev/data/<name>.txt
A list that is EMPTY in Supabase counts as "not synced yet" and falls back to the file, with a log line. The big lists are
cached on disk (AIDev/data/cache/) so a backend start does not download 1,000,000 adult domains every time.

Needs: package `psycopg` (already in Backend/requirements.txt) and DATABASE_URL (environment, AIDev/.env or Backend/.env).
Without them everything silently falls back to the files, exactly like before this module existed.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from aidev.core.common import DATA, ROOT, lines

log = logging.getLogger(__name__)
CACHE = DATA / "cache"
CONNECT_TIMEOUT = 8

# name in Supabase -> (table, column, local file used as the last fallback / as the sync source)
BIG = {
    "trusted_top_sites": ("trusted_top_sites", "domain", DATA / "tranco_top.txt"),
    "threat_feed_urls": ("threat_feed_urls", "url", DATA / "feeds_urls.txt"),
    "adult_domains": ("adult_domains", "domain", DATA / "adult_domains.txt"),
}
SMALL_TYPES = ("whitelist", "blacklist", "shared_hosts", "protected_domains", "not_trusted",
               "trusted_prefixes", "trusted_suffixes", "adult_manual")


def database_url() -> str | None:
    """DATABASE_URL from the environment, AIDev/.env (loaded by common.py) or Backend/.env."""
    url = os.getenv("DATABASE_URL")
    if url:
        return url.strip()
    f = ROOT.parent / "Backend" / ".env"
    try:
        for raw in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            raw = raw.strip()
            if raw.startswith("DATABASE_URL="):
                return raw.split("=", 1)[1].strip().strip('"').strip("'") or None
    except OSError:
        pass
    return None


def connect():
    """Open one short connection, or return None (no driver / no URL / cannot connect). Never raises."""
    url = database_url()
    if not url:
        return None
    try:
        import psycopg
        # prepare_threshold=None: also works through Supabase's transaction pooler (same as Backend/web/db.py)
        return psycopg.connect(url, connect_timeout=CONNECT_TIMEOUT, prepare_threshold=None)
    except Exception as exc:
        log.warning("Supabase not reachable (%s); lists come from local files", exc.__class__.__name__)
        return None


# ---------------------------------------------------------------- small lists
def small(list_type: str, fallback: Path | None = None, conn=None) -> list[str]:
    """Active entries of one detection_lists type, in insert order."""
    own = conn is None
    conn = conn or connect()
    rows: list[str] = []
    if conn is not None:
        try:
            with conn.cursor() as cur:
                cur.execute("select value from detection_lists where list_type = %s::detection_list_type "
                            "and is_active order by created_at, value", (list_type,))
                rows = [r[0] for r in cur.fetchall()]
        except Exception as exc:
            log.warning("could not read list %s (%s)", list_type, exc.__class__.__name__)
        finally:
            if own:
                conn.close()
    if rows:
        log.info("list %-18s %6d entries from Supabase", list_type, len(rows))
        return rows
    out = lines(fallback) if fallback else []
    log.info("list %-18s %6d entries from file (Supabase empty or not reachable)", list_type, len(out))
    return out


def setting(key: str, default, conn=None):
    """detection_settings value, converted to the type of `default`."""
    own = conn is None
    conn = conn or connect()
    if conn is not None:
        try:
            with conn.cursor() as cur:
                cur.execute("select value from detection_settings where key = %s", (key,))
                row = cur.fetchone()
            if row and str(row[0]).strip():
                return type(default)(str(row[0]).strip()) if default is not None else row[0]
        except Exception as exc:
            log.warning("could not read setting %s (%s)", key, exc.__class__.__name__)
        finally:
            if own:
                conn.close()
    return default


# ------------------------------------------------------------------ big lists
def _cache_file(name: str) -> Path:
    return CACHE / f"{name}.txt"


def _meta() -> dict:
    try:
        return json.loads((CACHE / "meta.json").read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save(name: str, values: list[str], remote: dict | None) -> None:
    try:
        CACHE.mkdir(parents=True, exist_ok=True)
        tmp = _cache_file(name).with_suffix(".tmp")
        tmp.write_text("\n".join(values), encoding="utf-8")
        tmp.replace(_cache_file(name))
        meta = _meta()
        meta[name] = remote or {}
        (CACHE / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    except OSError as exc:
        log.warning("could not write cache for %s: %s", name, exc)


def _remote_status(conn, name: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute("select row_count, synced_at::text from list_sync_status where name = %s", (name,))
        row = cur.fetchone()
    return {"row_count": int(row[0]), "synced_at": row[1]} if row else None


def _fetch_big(conn, name: str) -> list[str]:
    table, col, _ = BIG[name]
    order = " order by rank" if name == "trusted_top_sites" else ""
    out: list[str] = []
    with conn.cursor(name=f"fetch_{name}") as cur:           # server-side cursor: no 1,000,000-row spike
        cur.itersize = 50_000
        cur.execute(f"select {col} from {table}{order}")     # table/col come from the BIG constant, not from input
        for (v,) in cur:
            out.append(v)
    return out


def big(name: str, conn=None) -> list[str]:
    """One of the big lists, as a list of strings (trusted_top_sites is ordered by rank)."""
    _, _, local_file = BIG[name]
    cached = _cache_file(name)
    own = conn is None
    conn = conn or connect()
    status = None
    if conn is not None:
        try:
            status = _remote_status(conn, name)
            if status and cached.exists() and _meta().get(name) == status:
                vals = lines(cached)
                if vals:
                    log.info("list %-18s %7d entries from the local cache (Supabase version unchanged)", name, len(vals))
                    return vals
            vals = _fetch_big(conn, name)
            if vals:
                _save(name, vals, status)
                log.info("list %-18s %7d entries downloaded from Supabase", name, len(vals))
                return vals
            log.info("list %-18s is empty in Supabase (run: python -m aidev.pipeline.sync_to_supabase big)", name)
        except Exception as exc:
            log.warning("could not read %s from Supabase (%s)", name, exc.__class__.__name__)
        finally:
            if own:
                try:
                    conn.close()
                except Exception:
                    pass
    for src, label in ((cached, "stale cache"), (local_file, "local file")):
        vals = lines(src)
        if vals:
            log.info("list %-18s %7d entries from the %s", name, len(vals), label)
            return vals
    return []


def top_sites(limit: int | None = None, conn=None) -> list[str]:
    vals = big("trusted_top_sites", conn)
    return vals[:limit] if limit else vals


def feed_urls(conn=None) -> list[str]:
    return big("threat_feed_urls", conn)


def adult_domains(conn=None) -> list[str]:
    return big("adult_domains", conn)
