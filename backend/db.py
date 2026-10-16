"""Postgres (Supabase) access through a small connection pool. All queries use bound parameters."""
from __future__ import annotations

from contextlib import contextmanager

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

_pool: ConnectionPool | None = None




def init_pool(url: str) -> None:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            url, min_size=1, max_size=5, open=True,
            # prepare_threshold=None keeps this working on Supabase's transaction pooler too
            kwargs={"row_factory": dict_row, "prepare_threshold": None, "connect_timeout": 10},
        )
        _pool.wait(timeout=20)          # fail at start-up with a clear error if the URL/password is wrong


@contextmanager
def transaction():
    """Commits when the block ends normally, rolls back on any exception."""
    with _pool.connection() as conn:
        yield conn


def one(sql: str, params=()):
    with transaction() as c:
        return c.execute(sql, params).fetchone()


def run(sql: str, params=()) -> None:
    with transaction() as c:
        c.execute(sql, params)
