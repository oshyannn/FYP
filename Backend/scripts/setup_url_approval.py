"""Creates the tables behind the Whitelist and URL Approval screens (safe to run more than once).

Run from the Backend folder, with the venv active:   python -m scripts.setup_url_approval
It reads DATABASE_URL from Backend/.env, only CREATES what is missing and never changes or deletes existing data.
If a table with one of these names already exists but has different columns it stops and tells you, changing nothing.

  whitelist_requests : a user asks for a website to be trusted (employer / admin approve or reject)
  whitelist_entries  : trusted domains. scope 'user' = one person's own list, scope 'global' = set by an administrator
  threat_submissions : an employer reports a threat URL; an administrator approves (-> Global Threat List) or rejects

Row level security is switched on for the three tables with no policies, so only the backend (which connects as the
database owner) can read or write them; they are not reachable through the public Supabase API.
"""
from __future__ import annotations

import sys

import config
from web import db

REQUIRED = {
    "whitelist_requests": {"id", "user_id", "domain", "reason", "risk_score", "risk_level", "status", "review_note",
                           "reviewed_by", "reviewed_at", "created_at"},
    "whitelist_entries": {"id", "scope", "user_id", "domain", "added_by", "request_id", "created_at"},
    "threat_submissions": {"id", "submitted_by", "url", "domain", "url_hash", "category", "risk_score", "notes",
                           "review_status", "review_note", "reviewed_by", "reviewed_at", "global_url_id", "created_at"},
}

STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS public.whitelist_requests (
        id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        domain      text NOT NULL CHECK (char_length(domain) BETWEEN 3 AND 253),
        reason      text CHECK (reason IS NULL OR char_length(reason) <= 500),
        risk_score  numeric(5,2) CHECK (risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)),
        risk_level  text NOT NULL DEFAULT 'unknown' CHECK (risk_level IN ('safe', 'suspicious', 'malicious', 'unknown')),
        status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
        review_note text CHECK (review_note IS NULL OR char_length(review_note) <= 1000),
        reviewed_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
        reviewed_at timestamptz,
        created_at  timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS whitelist_requests_one_pending "
    "ON public.whitelist_requests (user_id, domain) WHERE status = 'pending'",
    "CREATE INDEX IF NOT EXISTS whitelist_requests_status_created ON public.whitelist_requests (status, created_at DESC)",
    """CREATE TABLE IF NOT EXISTS public.whitelist_entries (
        id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        scope      text NOT NULL CHECK (scope IN ('user', 'global')),
        user_id    uuid REFERENCES public.users(id) ON DELETE CASCADE,
        domain     text NOT NULL CHECK (char_length(domain) BETWEEN 3 AND 253),
        added_by   uuid REFERENCES public.users(id) ON DELETE SET NULL,
        request_id uuid REFERENCES public.whitelist_requests(id) ON DELETE SET NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        CHECK ((scope = 'user' AND user_id IS NOT NULL) OR (scope = 'global' AND user_id IS NULL))
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS whitelist_entries_user_domain "
    "ON public.whitelist_entries (user_id, domain) WHERE scope = 'user'",
    "CREATE UNIQUE INDEX IF NOT EXISTS whitelist_entries_global_domain "
    "ON public.whitelist_entries (domain) WHERE scope = 'global'",
    """CREATE TABLE IF NOT EXISTS public.threat_submissions (
        id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        submitted_by  uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        url           text NOT NULL CHECK (char_length(url) <= 2048),
        domain        text NOT NULL,
        url_hash      text NOT NULL,
        category      text NOT NULL CHECK (category IN ('phishing', 'malware', 'suspicious', 'spam', 'scam')),
        risk_score    numeric(5,2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
        notes         text NOT NULL CHECK (char_length(notes) BETWEEN 3 AND 1000),
        review_status text NOT NULL DEFAULT 'pending' CHECK (review_status IN ('pending', 'approved', 'rejected')),
        review_note   text CHECK (review_note IS NULL OR char_length(review_note) <= 1000),
        reviewed_by   uuid REFERENCES public.users(id) ON DELETE SET NULL,
        reviewed_at   timestamptz,
        global_url_id uuid REFERENCES public.global_urls(id) ON DELETE SET NULL,
        created_at    timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS threat_submissions_one_pending "
    "ON public.threat_submissions (url_hash) WHERE review_status = 'pending'",
    "CREATE INDEX IF NOT EXISTS threat_submissions_status_created "
    "ON public.threat_submissions (review_status, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS threat_submissions_by_user ON public.threat_submissions (submitted_by, created_at DESC)",
    "ALTER TABLE public.whitelist_requests ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.whitelist_entries ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.threat_submissions ENABLE ROW LEVEL SECURITY",
]


def _columns(c, table: str) -> dict[str, str]:
    rows = c.execute("SELECT column_name, data_type FROM information_schema.columns "
                     "WHERE table_schema = 'public' AND table_name = %s", (table,)).fetchall()
    return {r["column_name"]: r["data_type"] for r in rows}


def main() -> int:
    if not config.DATABASE_URL:
        print("DATABASE_URL is empty. Fill in Backend/.env first.")
        return 1
    db.init_pool(config.DATABASE_URL)
    with db.transaction() as c:                      # one transaction: either everything is created or nothing is
        problems = []
        for table, key in (("users", "id"), ("global_urls", "id")):
            col = _columns(c, table)
            if not col:
                problems.append(f"public.{table} does not exist.")
            elif col.get(key) != "uuid":
                problems.append(f"public.{table}.{key} is {col.get(key)!r}, expected uuid.")
        existing = {}
        for table, needed in REQUIRED.items():
            cols = _columns(c, table)
            existing[table] = bool(cols)
            if cols and not needed <= set(cols):
                problems.append(f"public.{table} already exists but is missing columns: {', '.join(sorted(needed - set(cols)))}.")
        if problems:
            print("Nothing was changed. Please send these lines back so the screens can be matched to your tables:")
            for p in problems:
                print("  -", p)
            return 1
        for sql in STATEMENTS:
            c.execute(sql)
    for table, was_there in existing.items():
        print(f"  {table}: {'already existed, kept as it is' if was_there else 'created'}")
    print("Done. Restart `python app.py`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
