"""A person's starred websites (Supabase table saved_urls).

GET    /api/saved-urls?search= &page= &per_page=    the caller's saved websites, newest first
POST   /api/saved-urls                              {"url", "title", "note", "risk_level", "risk_score"}: saves it (again = refreshes it)
GET    /api/saved-urls/check?url=                   is this address saved? {"saved": true, "item": {...}}
PATCH  /api/saved-urls/<id>                         {"note"}
POST   /api/saved-urls/<id>/rescan                  checks the address again and updates the saved verdict
DELETE /api/saved-urls/<id>                         removes it
DELETE /api/saved-urls?url=                         removes it by address (the star in the browser extension)

"risk_level" / "risk_score" are what the person saw when they saved it (the extension sends them); saving never runs a scan.
"""
from __future__ import annotations

import logging
import math

from flask import Blueprint, g, jsonify, request

from aidev.core.features import get_host, normalize
from aidev.detection.detector import analyze
from web.controllers.common import body, err, int_arg, s
from web.controllers.whitelist import parse_domain
from web.db_models import audit, saved_urls
from web.extensions import limiter
from web.guards import auth_required, role_required

log = logging.getLogger(__name__)
bp = Blueprint("saved_urls", __name__, url_prefix="/api")
LEVELS = {"safe": "safe", "suspicious": "suspicious", "malicious": "malicious", "unknown": "unknown"}


def _json(r) -> dict:
    return {"id": str(r["id"]), "url": r["url"], "domain": r["domain"], "title": r["title"], "note": r["note"],
            "risk_level": r["risk_level"], "risk_score": float(r["risk_score"]),
            "checked_at": r["checked_at"].isoformat() if r["checked_at"] else None,
            "saved_at": r["created_at"].isoformat()}


def _parse(raw: str):
    """(clean url, host, error)."""
    if not raw or len(raw) > 2048 or any(ord(ch) < 32 for ch in raw):
        return "", "", "Enter a valid website address."
    try:
        normalized = normalize(raw)
        host = get_host(normalized)
        clean = saved_urls.clean_url(normalized) if host else ""
    except ValueError:
        return "", "", "Enter a valid website address."
    if not host or len(host) > 253 or not clean.startswith(("http://", "https://")):
        return "", "", "Enter a valid website address."
    if parse_domain(host)[1]:                        # must look like a real domain name (example.com), not "not a url"
        return "", "", "Enter a valid website address."
    return clean, host, ""


def _score(v):
    try:
        n = float(v)
    except (TypeError, ValueError):
        return 0.0
    return round(min(100.0, max(0.0, n)), 2) if math.isfinite(n) else 0.0


@bp.get("/saved-urls")
@auth_required("user", "extension")
@role_required("user")
def list_saved():
    q = request.args.get("search", "").strip()[:200]
    per_page, page = int_arg("per_page", 10, 1, 50), int_arg("page", 1, 1, 100000)
    rows, total = saved_urls.list_page(g.user["id"], q, per_page, (page - 1) * per_page)
    return jsonify({"items": [_json(r) for r in rows], "total": total, "page": page, "per_page": per_page})


@bp.get("/saved-urls/check")
@auth_required("user", "extension")
@role_required("user")
def check_saved():
    clean, _host, problem = _parse(request.args.get("url", "").strip())
    if problem:
        return err("validation", problem, 400, {"url": problem})
    row = saved_urls.lookup(g.user["id"], clean)
    return jsonify({"saved": row is not None, "item": _json(row) if row else None})


@bp.post("/saved-urls")
@limiter.limit("120 per hour")
@auth_required("user", "extension")
@role_required("user")
def save_url():
    data = body()
    clean, host, problem = _parse(s(data, "url", 2048))
    if problem:
        return err("validation", problem, 400, {"url": problem})
    level = LEVELS.get(s(data, "risk_level", 12).lower())
    row, created = saved_urls.save(g.user["id"], clean, host, s(data, "title", 300) or None, s(data, "note", 500) or None,
                                   level or "unknown", _score(data.get("risk_score")) if level else 0.0, bool(level))
    if created:
        audit.log("saved_url_add", "saved_urls", g.user["id"], {"domain": host})
    return jsonify({"item": _json(row), "created": created}), 201 if created else 200


@bp.patch("/saved-urls/<uuid:saved_id>")
@limiter.limit("120 per hour")
@auth_required("user", "extension")
@role_required("user")
def edit_saved(saved_id):
    row = saved_urls.update_note(g.user["id"], saved_id, s(body(), "note", 500) or None)
    if not row:
        return err("not_found", "Saved website not found.", 404)
    return jsonify({"item": _json(row)})


@bp.post("/saved-urls/<uuid:saved_id>/rescan")
@limiter.limit("30 per hour")
@auth_required("user", "extension")
@role_required("user")
def rescan_saved(saved_id):
    row = saved_urls.get(g.user["id"], saved_id)
    if not row:
        return err("not_found", "Saved website not found.", 404)
    try:
        result = analyze(row["url"])
    except Exception:
        log.exception("analyze() failed for a saved website")
        return err("detector_unavailable", "Detection is temporarily unavailable. Try again.", 503)
    level = LEVELS.get(str(result.get("status", "")).lower(), "unknown")
    score = _score(result.get("risk_score"))
    return jsonify({"item": _json(saved_urls.update_verdict(g.user["id"], saved_id, level, score))})


@bp.delete("/saved-urls/<uuid:saved_id>")
@limiter.limit("120 per hour")
@auth_required("user", "extension")
@role_required("user")
def delete_saved(saved_id):
    if not saved_urls.delete(g.user["id"], saved_id):
        return err("not_found", "Saved website not found.", 404)
    return jsonify({"deleted": 1})


@bp.delete("/saved-urls")
@limiter.limit("120 per hour")
@auth_required("user", "extension")
@role_required("user")
def delete_saved_by_url():
    clean, _host, problem = _parse(request.args.get("url", "").strip())
    if problem:
        return err("validation", problem, 400, {"url": problem})
    if not saved_urls.delete_url(g.user["id"], clean):
        return err("not_found", "This website is not saved.", 404)
    return jsonify({"deleted": 1})
