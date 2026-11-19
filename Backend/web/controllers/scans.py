"""Scans and detection history for the desktop app and the extension.

POST   /api/scans              run the detector on a URL and save the result (history + threat list when risky)
GET    /api/scans              the caller's history: ?search= &status= &type= &page= &per_page=
GET    /api/scans/<id>         one record with the full analysis
DELETE /api/scans/<id>         delete one record
POST   /api/scans/delete       delete several records: {"ids": [...]}
POST   /api/scans/<id>/action  what the user chose after a warning: {"action": "proceeded" | "blocked" | "reported"}

The detector itself is not touched here: whatever `analyze()` returns is shown and stored as it is, so new signals
and fields added to the detector need no change in this file.
"""
from __future__ import annotations

import json
import logging
import uuid

from flask import Blueprint, g, jsonify, request

from aidev.core.features import get_host, normalize
from aidev.detection.detector import analyze
from web.controllers.common import body, err, s
from web.db_models import dynamic_scans, scans, whitelist
from web.extensions import limiter
from web.guards import auth_required
from web.services import dynamic_scanner

log = logging.getLogger(__name__)
bp = Blueprint("scans", __name__, url_prefix="/api")

LEVELS = {"safe": "safe", "suspicious": "suspicious", "malicious": "malicious", "unknown": "unknown"}
SCAN_TYPES = ("auto", "manual", "redirect")
THREAT_TYPES = ("none", "phishing", "malware", "spam", "defacement", "scam", "unwanted_software", "unknown")
MAX_BULK = 100
USER_ACTIONS = ("proceeded", "blocked", "reported")


def _scan_json(r, with_analysis: bool = False) -> dict:
    out = {
        "id": str(r["id"]), "url": r["url"], "domain": r["domain"], "scan_type": r["scan_type"],
        "user_action": r["user_action"], "scanned_at": r["scanned_at"].isoformat(),
        "risk_level": r["risk_level"], "risk_score": float(r["risk_score"]),
        "is_saved": bool(r.get("is_saved", False)),
    }
    if with_analysis:
        out["analysis"] = r["analysis"]
        out["threat_type"] = r.get("threat_type")
        out["list_status"] = r.get("list_status")
        out["detection_count"] = r.get("detection_count")
    return out


def _int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return min(hi, max(lo, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


def _trusted_scope(host: str):
    """'user' / 'global' when the host is on the caller's whitelist (or the administrator's), else None.
    A whitelist problem must never stop a scan."""
    try:
        return whitelist.trusted_scope(g.user["id"], host)
    except Exception:
        log.exception("whitelist lookup failed")
        return None


def _apply_whitelist(result: dict, level: str, score: float, threat: str, scope):
    """A trusted website is shown as safe, unless the detector found it malicious: that is never overridden."""
    if not scope or level == "safe":
        return result, level, score, threat
    whose = "the administrator's whitelist" if scope == "global" else "your whitelist"
    out = dict(result)
    reasons = list(out.get("reasons") or [])
    if level == "malicious":
        reasons.insert(0, f"This website is on {whose}, but it is not trusted because the detector found it malicious.")
        out.update(reasons=reasons, whitelist_ignored=scope)
        return out, level, score, threat
    reasons.insert(0, f"Trusted: this website is on {whose}.")
    out.update(status="Safe", risk_score=0, source="whitelist", reasons=reasons, whitelisted=scope,
               detector_status=result.get("status"), detector_score=result.get("risk_score"))
    return out, "safe", 0.0, "none"


@bp.post("/scans")
@limiter.limit("30 per minute; 300 per hour")
@auth_required("user", "extension")
def create_scan():
    data = body()
    url = s(data, "url", 2048)
    if not url or any(ord(ch) < 32 for ch in url):
        return err("validation", "Enter a website address to scan.", 400, {"url": "Enter a website address to scan."})
    url, defaulted_https = dynamic_scanner.normalize_scan_url(url)
    try:
        normalized = normalize(url)
        host = get_host(normalized)
        canon = scans.canonical_url(normalized) if host else ""
    except ValueError:
        host = canon = ""
    if not host or len(host) > 253:
        return err("validation", "Enter a valid website address.", 400, {"url": "Enter a valid website address."})

    try:
        result = analyze(url, use_ai=data.get("use_ai") is True)   # optional: also run the AI models when a list already decided the URL
    except Exception:                                   # a detector problem must not look like a server crash
        log.exception("analyze() failed")
        return err("detector_unavailable", "Detection is temporarily unavailable. Try again.", 503)

    level = LEVELS.get(str(result.get("status", "")).lower(), "unknown")
    score = min(100.0, max(0.0, float(result.get("risk_score") or 0)))
    threat = result.get("threat_type") if result.get("threat_type") in THREAT_TYPES else ("none" if level == "safe" else "unknown")
    result, level, score, threat = _apply_whitelist(result, level, score, threat, _trusted_scope(host))
    if g.user["portal"] == "extension":
        requested = s(data, "scan_type", 10)
        scan_type = requested if requested in SCAN_TYPES else "auto"
    else:
        scan_type = "manual"                            # the desktop app only ever scans by hand

    analysis = dict(result)
    if defaulted_https:
        reasons = list(analysis.get("reasons") or [])
        reasons.append("Scanned using HTTPS by default (plain HTTP was not scanned).")
        analysis["reasons"] = reasons
    if len(json.dumps(analysis, default=str)) > 20000:  # keep one row small whatever the detector returns
        analysis["reasons"] = list(analysis.get("reasons", []))[:50]
    saved = scans.record_scan(user_id=g.user["id"], url=url, canon=canon, domain=host, scan_type=scan_type,
                              level=level, score=score, threat_type=threat, analysis=analysis)
    rec = {"id": saved["id"], "url": url, "domain": host, "scan_type": scan_type, "user_action": "none",
           "scanned_at": saved["scanned_at"], "risk_level": level, "risk_score": score,
           "analysis": analysis, "threat_type": threat}
    return jsonify({"scan": _scan_json(rec, with_analysis=True)}), 201


@bp.get("/scans")
@auth_required("user", "extension")
def list_scans():
    q = request.args.get("search", "").strip()[:200]
    level = request.args.get("status", "").lower()
    stype = request.args.get("type", "").lower()
    per_page = _int("per_page", 10, 1, 50)
    page = _int("page", 1, 1, 100000)
    rows, total = scans.list_page(g.user["id"], q, level if level in LEVELS else "",
                                  stype if stype in SCAN_TYPES else "", per_page, (page - 1) * per_page)
    return jsonify({"scans": [_scan_json(r) for r in rows], "total": total, "page": page, "per_page": per_page})


@bp.get("/scans/<uuid:scan_id>")
@auth_required("user", "extension")
def get_scan(scan_id):
    r = scans.get_one(g.user["id"], scan_id)
    if not r:                                           # also what another user's record looks like: no leak
        return err("not_found", "Record not found.", 404)
    return jsonify({"scan": _scan_json(r, with_analysis=True)})


@bp.delete("/scans/<uuid:scan_id>")
@auth_required("user", "extension")
def delete_scan(scan_id):
    if not scans.delete_many(g.user["id"], [scan_id]):
        return err("not_found", "Record not found.", 404)
    return jsonify({"deleted": 1})


@bp.post("/scans/delete")
@limiter.limit("30 per minute")
@auth_required("user", "extension")
def delete_selected():
    raw = body().get("ids")
    if not isinstance(raw, list) or not raw or len(raw) > MAX_BULK:
        return err("validation", f"Select between 1 and {MAX_BULK} records.", 400)
    ids = []
    for item in raw:
        try:
            ids.append(uuid.UUID(str(item)))
        except ValueError:
            return err("validation", "Invalid record id.", 400)
    return jsonify({"deleted": scans.delete_many(g.user["id"], ids)})


@bp.post("/scans/<uuid:scan_id>/action")
@limiter.limit("120 per minute")
@auth_required("user", "extension")
def set_scan_action(scan_id):
    action = s(body(), "action", 20)
    if action not in USER_ACTIONS:
        return err("validation", "Invalid action.", 400, {"action": "Choose proceeded, blocked or reported."})
    if not scans.set_action(g.user["id"], scan_id, action):
        return err("not_found", "Record not found.", 404)
    return jsonify({"id": str(scan_id), "user_action": action})


def _dynamic_json(r) -> dict:
    return {
        "id": str(r["id"]),
        "history_id": str(r["history_id"]),
        "url": r["url"],
        "status": r["status"],
        "evidence": r["evidence"] or {},
        "ai2_dynamic": r["ai2_dynamic"],
        "error": r["error"],
        "duration_ms": r["duration_ms"],
        "created_at": r["created_at"].isoformat(),
        "updated_at": r["updated_at"].isoformat(),
    }


@bp.post("/scans/<uuid:scan_id>/dynamic")
@limiter.limit("10 per minute; 60 per hour")
@auth_required("user", "extension")
def start_dynamic_scan(scan_id):
    r = scans.get_one(g.user["id"], scan_id)
    if not r:
        return err("not_found", "Record not found.", 404)
    existing = dynamic_scans.latest_for_history(g.user["id"], scan_id)
    if existing and existing["status"] in ("queued", "running"):
        return jsonify({"dynamic": _dynamic_json(existing)}), 202
    if dynamic_scans.count_active_for_user(g.user["id"]) >= dynamic_scanner.MAX_USER_ACTIVE:
        return err("rate_limit", "Too many dynamic scans running. Wait for a scan to finish.", 429)
    ok, msg = dynamic_scanner.validate_public_url(r["url"])
    if not ok:
        return err("validation", msg, 400)
    job = dynamic_scanner.enqueue(scan_id, g.user["id"], r["url"])
    return jsonify({"dynamic": _dynamic_json(job)}), 202


@bp.get("/scans/<uuid:scan_id>/dynamic")
@auth_required("user", "extension")
def get_dynamic_scan(scan_id):
    r = scans.get_one(g.user["id"], scan_id)
    if not r:
        return err("not_found", "Record not found.", 404)
    job = dynamic_scans.latest_for_history(g.user["id"], scan_id)
    return jsonify({"dynamic": _dynamic_json(job) if job else None})
