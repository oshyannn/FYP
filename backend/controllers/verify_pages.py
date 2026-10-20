"""The only HTML in the backend: the page opened by the link in the verification email.
GET shows a confirm button (mail scanners that pre-open links therefore cannot verify an account by accident);
POST verifies. The desktop app that started the sign-up then signs in automatically."""
from __future__ import annotations

from flask import Blueprint, Response

from extensions import limiter
from models import audit, tokens, users

bp = Blueprint("verify_pages", __name__)

_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
_CSS = ("body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;"
        "font-family:Inter,system-ui,sans-serif;color:#1b2a41;background:linear-gradient(135deg,#f6f8fb,#eaf2fc)}"
        "main{width:100%;max-width:400px;padding:32px;text-align:center;background:#fff;border:1px solid #dde5f0;"
        "border-radius:16px;box-shadow:0 8px 24px rgba(30,58,95,.08)}"
        ".icon{width:56px;height:56px;margin:0 auto 12px;border-radius:16px;background:#1e3a5f;color:#fff;"
        "font-size:28px;line-height:56px}h1{margin:0 0 8px;font-size:22px;color:#14213a}"
        "p{margin:0 0 20px;font-size:14px;line-height:1.6;color:#52627a}"
        "button{width:100%;height:46px;border:0;border-radius:10px;background:#1e3a5f;color:#fff;"
        "font-size:14px;font-weight:600;cursor:pointer}button:focus-visible{outline:2px solid #1e3a5f;outline-offset:2px}")


def _page(title: str, text: str, button: str = "", status: int = 200) -> Response:
    form = f'<form method="post"><button type="submit">{button}</button></form>' if button else ""
    html = (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">'
            f"<title>{title} - SafeBrowse</title><style>{_CSS}</style></head><body><main>"
            f'<div class="icon">&#10003;</div><h1>{title}</h1><p>{text}</p>{form}</main></body></html>')
    resp = Response(html, status=status, mimetype="text/html")
    resp.headers["Content-Security-Policy"] = _CSP          # only these static, fixed strings are ever rendered
    return resp


_EXPIRED = ("Link expired", "This verification link is invalid or has expired. Open the SafeBrowse app and log in "
                            "to get a new email.")


@bp.get("/verify/<token>")
@limiter.limit("30 per hour")
def confirm_page(token):
    if len(token) > 100 or not tokens.peek_link(token):
        return _page(*_EXPIRED, status=400)
    return _page("Confirm your email", "Press the button to confirm your email address.", "Confirm email")


@bp.post("/verify/<token>")
@limiter.limit("20 per hour")
def confirm(token):
    uid = tokens.consume_link(token) if len(token) <= 100 else None
    if not uid:
        return _page(*_EXPIRED, status=400)
    users.mark_verified(uid)
    audit.log("email_verified", "auth", uid, {"via": "link"})
    return _page("Email verified", "You can go back to the SafeBrowse app. It signs you in automatically. "
                                   "You can close this tab.")
