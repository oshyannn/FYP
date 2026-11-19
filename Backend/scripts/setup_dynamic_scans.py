"""Creates the public.dynamic_scans table, indexes, RLS, and updated_at trigger in Supabase.

Run from the Backend folder: python -m scripts.setup_dynamic_scans
"""
from __future__ import annotations

import config
from web import db

STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS public.dynamic_scans (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      history_id uuid NOT NULL REFERENCES public.detection_history(id) ON DELETE CASCADE,
      user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
      url text NOT NULL,
      status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed', 'timed_out')),
      evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
      ai2_dynamic jsonb,
      error text,
      duration_ms integer,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_dynamic_scans_history_id ON public.dynamic_scans (history_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_dynamic_scans_user_id ON public.dynamic_scans (user_id, created_at DESC)",
    "ALTER TABLE public.dynamic_scans ENABLE ROW LEVEL SECURITY",
    "DROP TRIGGER IF EXISTS trg_dynamic_scans_updated_at ON public.dynamic_scans",
    """
    CREATE TRIGGER trg_dynamic_scans_updated_at
      BEFORE UPDATE ON public.dynamic_scans
      FOR EACH ROW
      EXECUTE FUNCTION public.set_updated_at()
    """,
]


def main() -> None:
    db.init_pool(config.DATABASE_URL)
    with db.transaction() as c:
        for stmt in STATEMENTS:
            c.execute(stmt)
    print("Created dynamic_scans table, indexes, RLS, and trigger successfully.")


if __name__ == "__main__":
    main()
