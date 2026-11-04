"""
Put the detector's lists into Supabase.          Run from the AIDev folder:

    python -m aidev.pipeline.sync_to_supabase lists            # small hand-made lists  (AIDev/lists/*.txt -> detection_lists)
    python -m aidev.pipeline.sync_to_supabase big              # Tranco, feeds, adult   (AIDev/data/*.txt  -> 3 big tables)
    python -m aidev.pipeline.sync_to_supabase big --only adult_domains
    python -m aidev.pipeline.sync_to_supabase all --dry-run    # count only, change nothing

lists : ADDS entries that are missing. It never deletes and never changes rows you made in the desktop app.
big   : REPLACES the whole table with the file (the files are rebuilt by `aidev.pipeline.feeds` / `import_adult`), in ONE
        transaction: readers see the old data until the new data is complete, and a failure changes nothing.
Needs DATABASE_URL (AIDev/.env or Backend/.env) and `psycopg`.
"""
from __future__ import annotations

import argparse
import re
import sys

from aidev.core.common import DATA, LISTS, lines
from aidev.core import list_store

# local file -> detection_list_type
SMALL_FILES = {
    "whitelist": "whitelist.txt", "blacklist": "blacklist.txt", "not_trusted": "not_trusted.txt",
    "protected_domains": "protected_domains.txt", "shared_hosts": "shared_hosts.txt",
    "trusted_prefixes": "trusted_prefixes.txt", "trusted_suffixes": "trusted_suffixes.txt",
    "adult_manual": "adult_manual.txt",
}
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://")
_WS = re.compile(r"\s")

INSERT_SMALL = ("insert into detection_lists (list_type, value, note) values (%s::detection_list_type, %s, %s) "
                "on conflict (list_type, value) do nothing")

# A table name / column can never come from the user: they are fixed in list_store.BIG
SQL_BIG = {
    "trusted_top_sites": ("domain, rank", "domain", "trusted_top_sites"),
    "threat_feed_urls": ("url, source", "url", "threat_feed_urls"),
    "adult_domains": ("domain", "domain", "adult_domains"),
}
UPSERT_STATUS = ("insert into list_sync_status (name, row_count, source, synced_at) values (%s, %s, %s, now()) "
                 "on conflict (name) do update set row_count = excluded.row_count, source = excluded.source, synced_at = now()")


def clean_value(v: str) -> str | None:
    """Same rules as the table checks, so one bad line cannot make the whole upload fail."""
    v = v.strip().lower()
    return v if v and not _WS.search(v) and not _SCHEME.match(v) else None


def small_rows() -> tuple[list[tuple[str, str, str]], dict[str, int]]:
    rows, skipped = [], {}
    for list_type, fname in SMALL_FILES.items():
        seen = set()
        for v in lines(LISTS / fname):
            c = clean_value(v)
            if c is None:
                skipped[list_type] = skipped.get(list_type, 0) + 1
            elif c not in seen:
                seen.add(c)
                rows.append((list_type, c, f"imported from lists/{fname}"))
    return rows, skipped


def big_rows(name: str, tranco_n: int) -> tuple[list[tuple], int, str]:
    """(rows, skipped, source label) for one big list."""
    _, _, path = list_store.BIG[name]
    seen: set[str] = set()
    rows: list[tuple] = []
    skipped = 0
    src = path.name
    vals = lines(path)
    if name == "trusted_top_sites":
        vals = vals[:tranco_n]
    for i, v in enumerate(vals, 1):
        if name == "threat_feed_urls":
            ok = v if len(v) <= 2048 and not _WS.search(v) else None      # lines() already lower-cased it
        else:
            ok = clean_value(v)
        if ok is None or ok in seen:
            skipped += ok is None
            continue
        seen.add(ok)
        rows.append((ok, i) if name == "trusted_top_sites" else (ok, "feeds") if name == "threat_feed_urls" else (ok,))
    return rows, skipped, src


def replace_table(conn, name: str, rows: list[tuple], source: str) -> None:
    cols, key, table = SQL_BIG[name]
    with conn.cursor() as cur:
        cur.execute(f"create temp table _new on commit drop as select {cols} from {table} with no data")   # only these columns, no NOT NULL from the target
        with cur.copy(f"copy _new ({cols}) from stdin") as cp:
            for r in rows:
                cp.write_row(r)
        cur.execute(f"delete from {table} t where not exists (select 1 from _new n where n.{key} = t.{key})")
        removed = cur.rowcount
        if name == "trusted_top_sites":      # keep the rank current for domains that stay
            cur.execute("update trusted_top_sites t set rank = n.rank from _new n where n.domain = t.domain and t.rank <> n.rank")
        cur.execute(f"insert into {table} ({cols}) select {cols} from _new on conflict ({key}) do nothing")
        cur.execute(UPSERT_STATUS, (name, len(rows), source))
    print(f"  {name:18} now {len(rows):>9} rows (removed {removed} old ones)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("what", choices=["lists", "big", "all"])
    ap.add_argument("--only", help="big lists only: trusted_top_sites, threat_feed_urls or adult_domains (comma separated)")
    ap.add_argument("--tranco-n", type=int, default=20_000, help="how many Tranco domains to upload (default 20000)")
    ap.add_argument("--dry-run", action="store_true", help="count only, change nothing")
    a = ap.parse_args(argv)

    plan_small = a.what in ("lists", "all")
    plan_big = [n for n in (a.only.split(",") if a.only else list_store.BIG) if a.what in ("big", "all")]
    bad = [n for n in plan_big if n not in list_store.BIG]
    if bad:
        print("unknown list:", ", ".join(bad), "| choose from:", ", ".join(list_store.BIG))
        return 2

    srows, sskipped = small_rows() if plan_small else ([], {})
    brows = {n: big_rows(n, a.tranco_n) for n in plan_big}

    print("Plan" + ("  (dry run: nothing will be changed)" if a.dry_run else ""))
    if plan_small:
        per: dict[str, int] = {}
        for t, _, _ in srows:
            per[t] = per.get(t, 0) + 1
        for t in SMALL_FILES:
            print(f"  {t:18} {per.get(t, 0):>9} entries from lists/{SMALL_FILES[t]}" + (f"  ({sskipped[t]} lines skipped)" if t in sskipped else ""))
    for n, (rows, skipped, src) in brows.items():
        print(f"  {n:18} {len(rows):>9} rows from data/{src}" + (f"  ({skipped} invalid lines skipped)" if skipped else "") + ("" if rows else "  <- file missing or empty, will NOT be uploaded"))
    if a.dry_run:
        return 0

    conn = list_store.connect()
    if conn is None:
        print("Cannot connect. Check DATABASE_URL (AIDev/.env or Backend/.env) and that `psycopg` is installed.")
        return 1
    try:
        if plan_small:
            with conn.cursor() as cur:
                cur.execute("select count(*) from detection_lists")
                before = cur.fetchone()[0]
                cur.executemany(INSERT_SMALL, srows)
                cur.execute("select count(*) from detection_lists")
                after = cur.fetchone()[0]
            conn.commit()
            print(f"Done: small lists, {len(srows)} entries checked, {after - before} new ones added (existing rows untouched).")
        for n, (rows, _, src) in brows.items():
            if not rows:
                print(f"  {n}: skipped (no data in data/{src}; run feeds.py / import_adult first)")
                continue
            replace_table(conn, n, rows, src)
            conn.commit()
    except Exception as exc:
        conn.rollback()
        print("FAILED, nothing from the failing step was saved:", exc)
        return 1
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
