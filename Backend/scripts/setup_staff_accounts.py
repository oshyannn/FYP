"""Creates the tables behind staff invitations and admin approvals (safe to run more than once).

Run from the Backend folder, with the venv active:   python -m scripts.setup_staff_accounts
It reads DATABASE_URL from Backend/.env, only CREATES what is missing and never changes or deletes existing data.
If a table with one of these names already exists but has different columns it stops and tells you, changing nothing.

  staff_invitations     : an administrator invites an employer or an administrator by email. The invited person
                          sets their own password with an emailed code. An invitation for an ADMINISTRATOR first
                          waits for another administrator's approval and also needs a PIN.
  admin_change_requests : one administrator asks to deactivate, activate or delete ANOTHER administrator's account;
                          a third administrator approves or rejects.

Row level security is switched on for both tables with no policies, so only the backend (which connects as the
database owner) can read or write them; they are not reachable through the public Supabase API.
"""
from __future__ import annotations

import sys

import config
from web import db

REQUIRED = {
    "staff_invitations": {"id", "email", "full_name", "role", "status", "invited_by", "code_hash", "code_expires_at",
                          "attempts", "pin_hash", "decided_by", "decided_at", "decision_note", "accepted_user_id",
                          "accepted_at", "created_at"},
    "admin_change_requests": {"id", "target_id", "action", "requested_by", "status", "decided_by", "decided_at",
                              "decision_note", "created_at"},
}

STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS public.staff_invitations (
        id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        email            text NOT NULL CHECK (char_length(email) <= 254),
        full_name        text NOT NULL CHECK (char_length(full_name) BETWEEN 2 AND 100),
        role             text NOT NULL CHECK (role IN ('employer', 'admin')),
        status           text NOT NULL DEFAULT 'sent'
                         CHECK (status IN ('awaiting_approval', 'sent', 'accepted', 'revoked', 'rejected', 'expired', 'locked')),
        invited_by       uuid REFERENCES public.users(id) ON DELETE SET NULL,
        code_hash        text,
        code_expires_at  timestamptz,
        attempts         integer NOT NULL DEFAULT 0,
        pin_hash         text,
        decided_by       uuid REFERENCES public.users(id) ON DELETE SET NULL,
        decided_at       timestamptz,
        decision_note    text CHECK (decision_note IS NULL OR char_length(decision_note) <= 1000),
        accepted_user_id uuid REFERENCES public.users(id) ON DELETE SET NULL,
        accepted_at      timestamptz,
        created_at       timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS staff_invitations_one_open_per_email "
    "ON public.staff_invitations (email) WHERE status IN ('awaiting_approval', 'sent')",
    "CREATE INDEX IF NOT EXISTS staff_invitations_status_created ON public.staff_invitations (status, created_at DESC)",
    """CREATE TABLE IF NOT EXISTS public.admin_change_requests (
        id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        target_id     uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
        action        text NOT NULL CHECK (action IN ('deactivate', 'activate', 'delete')),
        requested_by  uuid REFERENCES public.users(id) ON DELETE SET NULL,
        status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
        decided_by    uuid REFERENCES public.users(id) ON DELETE SET NULL,
        decided_at    timestamptz,
        decision_note text CHECK (decision_note IS NULL OR char_length(decision_note) <= 1000),
        created_at    timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS admin_change_requests_one_pending_per_target "
    "ON public.admin_change_requests (target_id) WHERE status = 'pending'",
    "CREATE INDEX IF NOT EXISTS admin_change_requests_status_created "
    "ON public.admin_change_requests (status, created_at DESC)",
    "ALTER TABLE public.staff_invitations ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE public.admin_change_requests ENABLE ROW LEVEL SECURITY",
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
        col = _columns(c, "users")
        if not col:
            problems.append("public.users does not exist.")
        elif col.get("id") != "uuid":
            problems.append(f"public.users.id is {col.get('id')!r}, expected uuid.")
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
