"""One-time database step for 'Forgot password: ask for help'.

Creates public.password_reset_requests (one waiting request per account; the row is kept after it is decided).
Run from the Backend folder, with the Backend virtual environment active:
    python -m scripts.setup_password_reset
Safe to run more than once. Changes no existing data.
"""
from web import db

STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS public.password_reset_requests (
           id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           user_id       uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
           status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
           created_at    timestamptz NOT NULL DEFAULT now(),
           decided_by    uuid REFERENCES public.users(id) ON DELETE SET NULL,
           decided_at    timestamptz,
           decision_note text
       )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS password_reset_one_pending "
    "ON public.password_reset_requests (user_id) WHERE status = 'pending'",
    "ALTER TABLE public.password_reset_requests ENABLE ROW LEVEL SECURITY",
]


def main() -> None:
    with db.transaction() as c:
        for sql in STATEMENTS:
            c.execute(sql)
    print("password_reset_requests is ready.")


if __name__ == "__main__":
    main()
