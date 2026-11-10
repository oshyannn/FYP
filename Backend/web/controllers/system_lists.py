"""The detector's own lists, managed from the staff screens (Supabase table detection_lists).

GET    /api/staff/system-lists?type=            employer / admin: one list (?search= &include_inactive=1 &page= &per_page=)
GET    /api/staff/system-lists/lookup?domain=   employer / admin: why a domain is (not) trusted (Tranco rank, entries)
POST   /api/staff/system-lists                  admin: {"type", "domain", "note"} adds (or switches back on) an entry
DELETE /api/staff/system-lists/<id>             admin: switches an entry off

type: whitelist | not_trusted | blacklist | adult_manual | adblock_block | adblock_allow (see db_models/system_lists.py)

Use `not_trusted` to take a popular (Tranco) site off the trusted list, and `blacklist` to always block a domain.
whitelist / not_trusted are stored as the registered domain (www.amazon.com -> amazon.com), because that is what the
detector compares. The detector reloads these lists straight after every change. This is different from /api/whitelist, which holds the
per-user and global "trusted websites" that the Backend applies after the detector (controllers/scans.py).
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from aidev.core.features import registered_domain
from web import detector_sync
from web.controllers.common import body, err, int_arg, s
from web.controllers.whitelist import parse_domain
from web.db_models import audit, system_lists
from web.extensions import limiter
from web.guards import auth_required, role_required

bp = Blueprint("system_lists", __name__, url_prefix="/api/staff")
TYPES = system_lists.TYPES


def _stored_value(list_type: str, host: str) -> str:
    """The detector compares whitelist / not_trusted with the REGISTERED domain (amazon.com, not www.amazon.com), so
    that is what is stored for them. blacklist and adult_manual also work for one host name (a.example.com)."""
    if list_type in ("whitelist", "not_trusted"):
        try:
            return registered_domain(f"https://{host}/") or host
        except Exception:
            return host
    return host


def _json(r) -> dict:
    return {"id": str(r["id"]), "type": r["list_type"], "domain": r["value"], "note": r["note"],
            "active": r["is_active"], "added_at": r["created_at"].isoformat(),
            "added_by": r["added_by_name"] or r["added_by_email"] or None}


@bp.get("/system-lists")
@auth_required("staff")
@role_required("employer", "admin")
def list_entries():
    list_type = request.args.get("type", "whitelist").lower()
    if list_type not in TYPES:
        return err("validation", "Choose one of: " + ", ".join(TYPES) + ".", 400, {"type": "Unknown list."})
    q = request.args.get("search", "").strip()[:100]
    include_inactive = request.args.get("include_inactive", "") in ("1", "true", "yes")
    per_page, page = int_arg("per_page", 50, 1, 100), int_arg("page", 1, 1, 100000)
    rows, total = system_lists.list_page(list_type, q, include_inactive, per_page, (page - 1) * per_page)
    return jsonify({"type": list_type, "entries": [_json(r) for r in rows], "total": total, "page": page,
                    "per_page": per_page})


@bp.get("/system-lists/lookup")
@auth_required("staff")
@role_required("employer", "admin")
def lookup():
    domain, problem = parse_domain(request.args.get("domain", "").strip()[:2048])
    if problem:
        return err("validation", problem, 400, {"domain": problem})
    return jsonify(system_lists.lookup(_stored_value("whitelist", domain)))


@bp.post("/system-lists")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("admin")
def add_entry():
    data = body()
    list_type = s(data, "type", 20).lower()
    if list_type not in TYPES:
        return err("validation", "Choose one of: " + ", ".join(TYPES) + ".", 400, {"type": "Unknown list."})
    domain, problem = parse_domain(s(data, "domain", 2048) or s(data, "url", 2048))
    if problem:
        return err("validation", problem, 400, {"domain": problem})
    domain = _stored_value(list_type, domain)
    note = s(data, "note", 500) or None
    outcome = system_lists.add(list_type, domain, note, g.user["id"])
    if outcome == "exists":
        return err("conflict", f"{domain} is already on the {list_type} list.", 409, {"domain": "Already on the list."})
    audit.log("system_list_add", "system_lists", g.user["id"], {"list": list_type, "domain": domain})
    detector_sync.reload_lists()
    return jsonify({"added": {"type": list_type, "domain": domain, "reactivated": outcome == "reactivated"}}), 201


@bp.delete("/system-lists/<uuid:entry_id>")
@limiter.limit("60 per hour")
@auth_required("staff")
@role_required("admin")
def remove_entry(entry_id):
    row = system_lists.deactivate(entry_id)
    if row is None:
        return err("not_found", "Entry not found.", 404)
    audit.log("system_list_remove", "system_lists", g.user["id"], {"list": row["list_type"], "domain": row["value"]})
    detector_sync.reload_lists()
    return jsonify({"deleted": 1})
