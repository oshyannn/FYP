"""Small helpers shared by the JSON controllers."""
from __future__ import annotations

from flask import jsonify, request


def err(code: str, message: str, status: int, fields: dict | None = None):
    body = {"error": {"code": code, "message": message}}
    if fields:
        body["error"]["fields"] = fields
    return jsonify(body), status


def body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def s(data: dict, key: str, maxlen: int = 256) -> str:
    """A trimmed string field, or '' if missing / not a string."""
    v = data.get(key)
    return v.strip()[:maxlen] if isinstance(v, str) else ""


def raw(data: dict, key: str, maxlen: int = 128) -> str:        # passwords are never trimmed
    v = data.get(key)
    return v[:maxlen] if isinstance(v, str) else ""


def int_arg(name: str, default: int, lo: int, hi: int) -> int:
    """A clamped integer from the query string (bad input falls back to the default)."""
    try:
        return min(hi, max(lo, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default
