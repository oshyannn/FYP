"""One-time check for User Management and Activity Logs (safe to run more than once).

Run from the Backend folder, with the venv active:   python -m scripts.setup_user_management
It reads DATABASE_URL from Backend/.env. It never changes or deletes data. The only thing it can do is ADD a
missing label to a database enum type, and only when one is really missing:

  1. Deactivating an account needs a label in public.account_status other than 'active' / 'pending'.
     It uses the first of: inactive, suspended, deactivated, disabled, blocked. If your type has none, it adds 'inactive'.
  2. If public.activity_logs.module or .action are enum columns (instead of plain text), the audit log can only store
     values the enum knows. This adds the ones the backend writes and the type does not have yet.
     Plain text columns need nothing.
"""
from __future__ import annotations

import sys

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

import config

PREFERRED_DISABLED = ("inactive", "suspended", "deactivated", "disabled", "blocked")

# what web/db_models/audit.py is asked to write; only relevant when the columns are enums
MODULES = ("auth", "account", "extension", "feedback", "employer_verification", "threat_list", "whitelist",
           "user_management")
ACTIONS = ("user_activated", "user_deactivated", "user_updated", "whitelist_add", "whitelist_remove",
           "whitelist_request", "whitelist_request_approve", "whitelist_request_reject",
           "threat_submission_create", "threat_submission_approve", "threat_submission_reject")


def labels(conn, schema: str, name: str) -> list[str]:
    rows = conn.execute(
        "SELECT e.enumlabel AS label FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid "
        "JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = %s AND t.typname = %s "
        "ORDER BY e.enumsortorder", (schema, name)).fetchall()
    return [r["label"] for r in rows]


def add_label(conn, schema: str, name: str, label: str) -> None:
    conn.execute(sql.SQL("ALTER TYPE {}.{} ADD VALUE IF NOT EXISTS {}").format(
        sql.Identifier(schema), sql.Identifier(name), sql.Literal(label)))


def main() -> int:
    if not config.DATABASE_URL:
        print("DATABASE_URL is empty. Fill in Backend/.env first.")
        return 1
    # autocommit: adding an enum label cannot be used in the same transaction anyway
    with psycopg.connect(config.DATABASE_URL, autocommit=True, row_factory=dict_row, prepare_threshold=None,
                         connect_timeout=10) as conn:
        # 1. the label for a deactivated account
        have = labels(conn, "public", "account_status")
        if not have:
            print("public.account_status was not found as an enum type. Nothing was changed.")
            print("Please send this line back so the screen can be matched to your table.")
            return 1
        print(f"account_status has: {', '.join(have)}")
        found = next((x for x in PREFERRED_DISABLED if x in have), None)
        if found:
            print(f"  deactivated accounts will use '{found}'. Nothing to add.")
        else:
            add_label(conn, "public", "account_status", "inactive")
            print("  no label for a deactivated account existed: added 'inactive'.")

        # 2. the audit log columns
        cols = conn.execute(
            "SELECT column_name, data_type, udt_schema, udt_name FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'activity_logs' AND column_name IN ('module', 'action')"
        ).fetchall()
        if not cols:
            print("public.activity_logs was not found. Nothing was changed.")
            return 1
        for c in cols:
            wanted = MODULES if c["column_name"] == "module" else ACTIONS
            if c["data_type"] != "USER-DEFINED":
                print(f"activity_logs.{c['column_name']} is plain text ({c['data_type']}): nothing to add.")
                continue
            have = set(labels(conn, c["udt_schema"], c["udt_name"]))
            missing = [x for x in wanted if x not in have]
            for x in missing:
                add_label(conn, c["udt_schema"], c["udt_name"], x)
            print(f"activity_logs.{c['column_name']} is an enum ({c['udt_name']}): "
                  + (f"added {', '.join(missing)}." if missing else "it already knows every value. Nothing to add."))
    print("Done. Restart `python app.py`.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
