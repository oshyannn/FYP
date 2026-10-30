"""Attaches the secure API layer (rate limits, headers, bearer auth, routes) to the Flask app."""
from __future__ import annotations

from flask import g, jsonify, request
from werkzeug.exceptions import HTTPException

import config
from web import db
from web.extensions import limiter
from web.guards import load_current_user


def init_web(app):
    problems = config.validate()
    if problems:
        raise RuntimeError("Auth settings problem:\n - " + "\n - ".join(problems))

    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        MAX_CONTENT_LENGTH=64 * 1024,
        RATELIMIT_STORAGE_URI="memory://",       # single process; use Redis if you ever run several workers
    )
    db.init_pool(config.DATABASE_URL)
    limiter.init_app(app)

    from web.controllers.api_auth import bp
    app.register_blueprint(bp)
    from web.controllers.verify_pages import bp as verify_bp
    app.register_blueprint(verify_bp)
    from web.controllers.scans import bp as scans_bp
    app.register_blueprint(scans_bp)
    from web.controllers.employers import bp as employers_bp
    app.register_blueprint(employers_bp)
    from web.controllers.threats import bp as threats_bp
    app.register_blueprint(threats_bp)
    from web.controllers.feedback import bp as feedback_bp
    app.register_blueprint(feedback_bp)
    from web.controllers.dashboard import bp as dashboard_bp
    app.register_blueprint(dashboard_bp)

    @app.before_request
    def _load_user():
        g.user = None
        if request.endpoint not in (None, "static"):
            load_current_user()                  # no Authorization header = no database work

    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        if config.HTTPS:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        origin = request.headers.get("Origin")
        if origin and origin in config.CORS_ORIGINS:          # explicit allow-list only
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
            resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        return resp

    @app.errorhandler(HTTPException)
    def _json_errors(e):
        message = "Too many requests. Try again later." if e.code == 429 else e.name
        return jsonify({"error": {"code": e.name.lower().replace(" ", "_"), "message": message}}), e.code
