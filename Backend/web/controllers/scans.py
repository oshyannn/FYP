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
from web.db_models import scans
from web.extensions import limiter
from web.guards import auth_required

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


@bp.post("/scans")
@limiter.limit("30 per minute; 300 per hour")
@auth_required("user", "extension")
def create_scan():
    data = body()
    url = s(data, "url", 2048)
    if not url or any(ord(ch) < 32 for ch in url):
        return err("validation", "Enter a website address to scan.", 400, {"url": "Enter a website address to scan."})
    try:
        normalized = normalize(url)
        host = get_host(normalized)
        canon = scans.canonical_url(normalized) if host else ""
    except ValueError:
        host = canon = ""
    if not host or len(host) > 253:
        return err("validation", "Enter a valid website address.", 400, {"url": "Enter a valid website address."})

    try:
        result = analyze(url)
    except Exception:                                   # a detector problem must not look like a server crash
        log.exception("analyze() failed")
        return err("detector_unavailable", "Detection is temporarily unavailable. Try again.", 503)

    level = LEVELS.get(str(result.get("status", "")).lower(), "unknown")
    score = min(100.0, max(0.0, float(result.get("risk_score") or 0)))
    threat = result.get("threat_type") if result.get("threat_type") in THREAT_TYPES else ("none" if level == "safe" else "unknown")
    if g.user["portal"] == "extension":
        requested = s(data, "scan_type", 10)
        scan_type = requested if requested in SCAN_TYPES else "auto"
    else:
        scan_type = "manual"                            # the desktop app only ever scans by hand

    analysis = dict(result)
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
