"""Adds the two columns behind temporary passwords (safe to run more than once).

Run from the Backend folder, with the venv active:   python -m scripts.setup_forced_password_change
Run it BEFORE restarting `python app.py` with the new code, because the login query now reads these columns.

  users.must_change_password      true while the account has a temporary password: the person can do nothing but
                                  choose their own password (the server enforces this on every request).
  users.temp_password_expires_at  the temporary password stops working after this time.

It only ADDS columns that are missing and never changes or deletes existing data.
"""
from __future__ import annotations

import sys

import config
from web import db

STATEMENTS = [
    "ALTER TABLE public.users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false",
    "ALTER TABLE public.users ADD COLUMN IF NOT EXISTS temp_password_expires_at timestamptz",
]


def main() -> int:
    if not config.DATABASE_URL:
        print("DATABASE_URL is empty. Fill in Backend/.env first.")
        return 1
    db.init_pool(config.DATABASE_URL)
    with db.transaction() as c:
        exists = c.execute("SELECT 1 FROM information_schema.columns "
                           "WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'id'").fetchone()
        if not exists:
            print("public.users does not exist. Nothing was changed.")
            return 1
        for sql in STATEMENTS:
            c.execute(sql)
    print("Done: users.must_change_password and users.temp_password_expires_at exist. Restart `python app.py`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
