"""A person's own decision per website: always allow it, or always block it (Supabase table url_lists).

GET    /api/site-rules                 the caller's rules
PUT    /api/site-rules                 {"host" | "url", "rule": "allow" | "block", "note"}: adds or changes the rule
DELETE /api/site-rules/<id>            removes one rule (the warning comes back)
DELETE /api/site-rules?host=           same, by website (the browser extension uses this)

The browser extension reads these rules and applies them (extension/background.js): "allow" = no warning for that website,
"block" = always blocked. The choices that are not permanent ("just this once", "for 1 hour", "until the browser closes")
are kept by the extension only. "allow" may also silence a warning about a known threat: that is the person's own choice,
and every scan is still saved in their history.
"""
from __future__ import annotations

from flask import Blueprint, g, jsonify, request

from web.controllers.common import body, err, s
from web.controllers.whitelist import parse_domain
from web.db_models import audit, site_rules
from web.extensions import limiter
from web.guards import auth_required, role_required

bp = Blueprint("site_rules", __name__, url_prefix="/api")
RULES = ("allow", "block")


def _host(raw: str) -> tuple[str, str]:
    host, problem = parse_domain(raw)
    return (host[4:] if host.startswith("www.") else host), problem


def _json(r) -> dict:
    return {"id": str(r["id"]), "host": r["url"].split("://", 1)[-1].strip("/"), "rule": r["rule"], "note": r["note"],
            "created_at": r["created_at"].isoformat()}


@bp.get("/site-rules")
@auth_required("user", "extension")
@role_required("user")
def list_rules():
    return jsonify({"rules": [_json(r) for r in site_rules.list_rules(g.user["id"])]})


@bp.put("/site-rules")
@limiter.limit("120 per hour")
@auth_required("user", "extension")
@role_required("user")
def put_rule():
    data = body()
    rule = s(data, "rule", 10).lower()
    if rule not in RULES:
        return err("validation", "Choose allow or block.", 400, {"rule": "Choose allow or block."})
    host, problem = _host(s(data, "host", 2048) or s(data, "url", 2048))
    if problem:
        return err("validation", problem, 400, {"host": problem})
    row = site_rules.set_rule(g.user["id"], host, rule, s(data, "note", 300) or None)
    audit.log("site_rule_set", "site_rules", g.user["id"], {"host": host, "rule": rule})
    return jsonify({"rule": _json(row)}), 200


@bp.delete("/site-rules/<uuid:rule_id>")
@limiter.limit("120 per hour")
@auth_required("user", "extension")
@role_required("user")
def delete_rule(rule_id):
    if not site_rules.delete(g.user["id"], rule_id):
        return err("not_found", "Rule not found.", 404)
    audit.log("site_rule_remove", "site_rules", g.user["id"], {"rule_id": str(rule_id)})
    return jsonify({"deleted": 1})


@bp.delete("/site-rules")
@limiter.limit("120 per hour")
@auth_required("user", "extension")
@role_required("user")
def delete_rule_by_host():
    host, problem = _host(request.args.get("host", "").strip()[:2048])
    if problem:
        return err("validation", problem, 400, {"host": problem})
    if not site_rules.delete_host(g.user["id"], host):
        return err("not_found", "No rule for this website.", 404)
    audit.log("site_rule_remove", "site_rules", g.user["id"], {"host": host})
    return jsonify({"deleted": 1})
