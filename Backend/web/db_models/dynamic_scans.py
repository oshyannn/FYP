"""Dynamic browser scan jobs (Model layer): public.dynamic_scans."""
from __future__ import annotations

from psycopg.types.json import Jsonb

from web import db

_COLS = "id, history_id, user_id, url, status, evidence, ai2_dynamic, error, duration_ms, created_at, updated_at"


def create_job(history_id, user_id, url: str):
    return db.one(
        f"INSERT INTO public.dynamic_scans (history_id, user_id, url, status) "
        f"VALUES (%s, %s, %s, 'queued') RETURNING {_COLS}",
        (history_id, user_id, url),
    )


def set_running(job_id) -> None:
    db.run("UPDATE public.dynamic_scans SET status = 'running' WHERE id = %s", (job_id,))


def finish_job(job_id, status: str, evidence: dict, ai2_dynamic: dict | None, error: str | None, duration_ms: int | None) -> None:
    db.run(
        "UPDATE public.dynamic_scans "
        "SET status = %s, evidence = %s, ai2_dynamic = %s, error = %s, duration_ms = %s "
        "WHERE id = %s",
        (status, Jsonb(evidence), Jsonb(ai2_dynamic) if ai2_dynamic is not None else None, error, duration_ms, job_id),
    )


def latest_for_history(user_id, history_id):
    return db.one(
        f"SELECT {_COLS} FROM public.dynamic_scans "
        "WHERE user_id = %s AND history_id = %s ORDER BY created_at DESC LIMIT 1",
        (user_id, history_id),
    )


def count_active_for_user(user_id) -> int:
    row = db.one(
        "SELECT count(*) AS n FROM public.dynamic_scans WHERE user_id = %s AND status IN ('queued', 'running')",
        (user_id,),
    )
    return int(row["n"]) if row else 0
