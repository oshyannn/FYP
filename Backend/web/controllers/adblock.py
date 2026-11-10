"""Extra ad / tracker domains for the browser extension's Shields (administrator-managed, Supabase detection_lists).

GET /api/adblock/lists    signed-in extension / user / staff: {"block": [domain, ...], "allow": [domain, ...]}

The extension ships EasyList / EasyPrivacy rulesets of its own; these two lists let an administrator block one more
ad network, or stop the extension from breaking a website, without a new extension release. Changes reach the
extension within about 6 hours (or on its next start).
"""
from __future__ import annotations

from flask import Blueprint, jsonify

from web.db_models import system_lists
from web.extensions import limiter
from web.guards import auth_required

bp = Blueprint("adblock", __name__, url_prefix="/api")


@bp.get("/adblock/lists")
@limiter.limit("120 per hour")
@auth_required("user", "extension", "staff")
def lists():
    return jsonify(system_lists.adblock_domains())
