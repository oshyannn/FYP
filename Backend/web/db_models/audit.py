"""Writes security events to public.activity_logs. Never log passwords or tokens."""
from __future__ import annotations

import logging

from flask import has_request_context, request
from psycopg.types.json import Jsonb

from web import db

_log = logging.getLogger(__name__)


def log(action: str, module: str, user_id=None, details: dict | None = None) -> None:
    ip = ua = None
    if has_request_context():
        ip = request.remote_addr
        ua = (request.user_agent.string or "")[:300]
    try:
        db.run("INSERT INTO public.activity_logs (user_id, action, module, details, ip_address, user_agent) "
               "VALUES (%s, %s, %s, %s, %s::inet, %s)",
               (user_id, action, module, Jsonb(details or {}), ip, ua))
    except Exception:                                  # an audit failure must never block a login
        _log.exception("audit log failed")
