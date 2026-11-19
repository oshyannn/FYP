"""Isolated Playwright/Chromium dynamic webpage scanner worker.

Outputs a single bounded JSON object (schema_version=1) to stdout.
Never raises uncaught exceptions to callers; errors and timeouts produce structured JSON.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import threading
import time
import uuid
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

SCHEMA_VERSION = 1
NAV_TIMEOUT_MS = int(os.getenv("SCAN_NAV_TIMEOUT_MS", "25000"))
POST_LOAD_WAIT_MS = int(os.getenv("SCAN_POST_LOAD_MS", "3000"))
TOTAL_BUDGET_S = float(os.getenv("SCAN_TOTAL_BUDGET_S", "40.0"))
MAX_REDIRECTS = int(os.getenv("SCAN_MAX_REDIRECTS", "10"))
MAX_REQUESTS = int(os.getenv("SCAN_MAX_REQUESTS", "200"))
MAX_SCRIPTS = int(os.getenv("SCAN_MAX_SCRIPTS", "100"))
MAX_DOM_BYTES = int(os.getenv("SCAN_MAX_DOM_BYTES", str(1024 * 1024)))
MAX_OUTPUT_BYTES = int(os.getenv("SCAN_MAX_OUTPUT_BYTES", str(2 * 1024 * 1024)))
ALLOW_PRIVATE = os.getenv("ALLOW_PRIVATE_FIXTURES", "0") == "1"


_DNS_CACHE: dict[str, bool] = {}


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
        return ip.is_global and not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        )
    except ValueError:
        return False


def _validate_url_and_dns(raw_url: str, allow_private: bool = False) -> tuple[bool, str, str]:
    """Returns (ok, canonical_or_raw, error_reason)."""
    try:
        parts = urlsplit(raw_url.strip())
    except ValueError:
        return False, raw_url, "Malformed URL"
    if parts.scheme.lower() not in ("http", "https"):
        return False, raw_url, f"Unsupported scheme: {parts.scheme or 'none'}"
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        return False, raw_url, "Missing hostname"
    if allow_private:
        return True, raw_url, ""
    if host in _DNS_CACHE:
        return (_DNS_CACHE[host], raw_url, "" if _DNS_CACHE[host] else "Blocked non-public IP destination")
    try:
        socket.setdefaulttimeout(3.0)
        infos = socket.getaddrinfo(host, None)
    except OSError:
        _DNS_CACHE[host] = False
        return False, raw_url, "DNS resolution failed"
    addrs = {i[4][0] for i in infos}
    ok = bool(addrs) and all(_is_public_ip(a) for a in addrs)
    _DNS_CACHE[host] = ok
    if not ok:
        return False, raw_url, "Blocked non-public IP destination"
    return True, raw_url, ""


def _safe_host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def scan(url: str, scan_id: str, allow_private: bool = False) -> dict:
    t0 = time.monotonic()
    limitations: list[str] = [
        "Dynamic observation is limited to the configured runtime window; delayed behaviour after the window may not be captured."
    ]
    result: dict = {
        "schema_version": SCHEMA_VERSION,
        "scan_id": scan_id,
        "requested_url": url,
        "final_url": url,
        "status": "failed",
        "duration_ms": 0,
        "navigation": {"redirect_count": 0, "redirect_urls": [], "http_status": None},
        "network": {"request_count": 0, "external_domains": [], "failed_request_count": 0, "blocked_ssrf_count": 0},
        "scripts": {"external_script_count": 0, "inline_script_count": 0, "script_urls": []},
        "dom": {
            "snapshot_captured": False,
            "rendered_html": "",
            "form_count": 0,
            "password_field_count": 0,
            "iframe_count": 0,
            "external_form_actions": [],
        },
        "behaviour": {
            "popup_count": 0,
            "download_attempt_count": 0,
            "download_filenames": [],
            "console_error_count": 0,
            "page_error_count": 0,
        },
        "limitations": limitations,
        "error": None,
    }

    ok, _, reason = _validate_url_and_dns(url, allow_private=allow_private)
    if not ok:
        result["error"] = reason
        result["duration_ms"] = round((time.monotonic() - t0) * 1000)
        return result

    redirect_urls: list[str] = []
    ext_domains: set[str] = set()
    script_urls: list[str] = []
    seen_scripts: set[str] = set()
    req_count = 0
    failed_req_count = 0
    blocked_ssrf_count = 0
    popup_count = 0
    download_count = 0
    download_names: list[str] = []
    console_err_count = 0
    page_err_count = 0
    req_host = _safe_host(url)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--no-first-run",
                    "--disable-background-networking",
                    "--disable-default-apps",
                    "--disable-extensions",
                    "--disable-sync",
                ],
            )
            context = browser.new_context(
                accept_downloads=False,
                ignore_https_errors=True,
                java_script_enabled=True,
                permissions=[],
                viewport={"width": 1280, "height": 800},
            )
            context.set_default_timeout(5000)

            def _watchdog():
                result["duration_ms"] = round((time.monotonic() - t0) * 1000)
                if result["status"] == "failed":
                    result["status"] = "partial" if result["dom"]["snapshot_captured"] or req_count > 0 else "timed_out"
                if "Browser exceeded runtime budget; partial results returned." not in result["limitations"]:
                    result["limitations"].append("Browser exceeded runtime budget; partial results returned.")
                sys.stdout.write(json.dumps(result))
                sys.stdout.flush()
                os._exit(0)

            timer = threading.Timer(TOTAL_BUDGET_S, _watchdog)
            timer.daemon = True
            timer.start()

            def handle_route(route):
                nonlocal blocked_ssrf_count
                r_url = route.request.url
                r_ok, _, _ = _validate_url_and_dns(r_url, allow_private=allow_private)
                if not r_ok:
                    blocked_ssrf_count += 1
                    route.abort("blockedbyclient")
                    return
                if route.request.resource_type in ("media", "font"):
                    route.abort("blockedbyclient")
                    return
                if req_count >= MAX_REQUESTS:
                    route.abort("blockedbyclient")
                    return
                route.continue_()

            context.route("**/*", handle_route)
            page = context.new_page()

            def on_request(req):
                nonlocal req_count
                req_count += 1
                h = _safe_host(req.url)
                if h and h != req_host:
                    ext_domains.add(h)
                if req.resource_type == "script" and len(script_urls) < MAX_SCRIPTS:
                    if req.url not in seen_scripts:
                        seen_scripts.add(req.url)
                        script_urls.append(req.url[:512])
                if req.is_navigation_request() and req.frame == page.main_frame:
                    if len(redirect_urls) < MAX_REDIRECTS and req.url not in redirect_urls:
                        redirect_urls.append(req.url[:1024])

            def on_request_failed(_req):
                nonlocal failed_req_count
                failed_req_count += 1

            def on_popup(popup):
                nonlocal popup_count
                popup_count += 1
                try:
                    popup.close()
                except Exception:
                    pass

            def on_download(dl):
                nonlocal download_count
                download_count += 1
                try:
                    if len(download_names) < 10:
                        download_names.append(dl.suggested_filename[:128])
                    dl.cancel()
                except Exception:
                    pass

            def on_console(msg):
                nonlocal console_err_count
                if msg.type == "error":
                    console_err_count += 1

            def on_page_error(_err):
                nonlocal page_err_count
                page_err_count += 1

            page.on("request", on_request)
            page.on("requestfailed", on_request_failed)
            page.on("popup", on_popup)
            page.on("download", on_download)
            page.on("console", on_console)
            page.on("pageerror", on_page_error)

            def _capture_dom() -> None:
                nonlocal final_url, final_host
                final_url = page.url or url
                final_host = _safe_host(final_url)
                dom_info = None
                for _attempt in range(2):
                    try:
                        dom_info = page.evaluate(
                            """() => {
                                const forms = Array.from(document.querySelectorAll('form'));
                                const actions = forms.map(f => f.getAttribute('action') || '').filter(Boolean).slice(0, 50);
                                return {
                                    formCount: forms.length,
                                    passwordCount: document.querySelectorAll('input[type="password"]').length,
                                    iframeCount: document.querySelectorAll('iframe').length,
                                    inlineScripts: Array.from(document.querySelectorAll('script:not([src])')).length,
                                    actions,
                                    html: document.documentElement ? document.documentElement.outerHTML : ''
                                };
                            }"""
                        )
                        break
                    except Exception:
                        try:
                            page.wait_for_timeout(400)
                        except Exception:
                            pass

                raw_html = ""
                if dom_info is not None:
                    raw_html = dom_info.get("html") or ""
                else:
                    try:
                        raw_html = page.content() or ""
                    except Exception:
                        raw_html = ""

                if raw_html or dom_info is not None:
                    if len(raw_html.encode("utf-8", errors="ignore")) > MAX_DOM_BYTES:
                        raw_html = raw_html[: MAX_DOM_BYTES // 2]
                        if "Rendered DOM exceeded 1 MB cap and was truncated." not in limitations:
                            limitations.append("Rendered DOM exceeded 1 MB cap and was truncated.")

                    ext_actions = []
                    for act in (dom_info or {}).get("actions") or []:
                        ah = _safe_host(act)
                        if ah and ah != final_host and ah not in ext_actions:
                            ext_actions.append(ah)

                    result["dom"] = {
                        "snapshot_captured": bool(raw_html),
                        "rendered_html": raw_html,
                        "form_count": int((dom_info or {}).get("formCount") or 0),
                        "password_field_count": int((dom_info or {}).get("passwordCount") or 0),
                        "iframe_count": int((dom_info or {}).get("iframeCount") or 0),
                        "external_form_actions": ext_actions[:20],
                    }
                    result["scripts"]["inline_script_count"] = int((dom_info or {}).get("inlineScripts") or 0)

            final_url = url
            final_host = _safe_host(url)
            timed_out = False
            http_status = None
            try:
                resp = page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                if resp is not None:
                    http_status = resp.status
                _capture_dom()  # Checkpoint 1: capture immediately on domcontentloaded
                remaining_ms = max(0, int((TOTAL_BUDGET_S - (time.monotonic() - t0)) * 1000))
                wait_ms = min(POST_LOAD_WAIT_MS, remaining_ms)
                if wait_ms > 200:
                    page.wait_for_timeout(wait_ms)
            except Exception as nav_exc:
                if "Timeout" in type(nav_exc).__name__ or "timeout" in str(nav_exc).lower():
                    timed_out = True
                    limitations.append("Page load exceeded navigation timeout; partial DOM and events captured.")
                else:
                    result["error"] = f"Navigation error: {type(nav_exc).__name__}"

            _capture_dom()  # Checkpoint 2: capture post-load / delayed JS changes
            if not result["dom"]["snapshot_captured"]:
                limitations.append("DOM snapshot could not be captured.")

            result["final_url"] = final_url
            result["navigation"] = {
                "redirect_count": max(0, len(redirect_urls) - 1),
                "redirect_urls": redirect_urls,
                "http_status": http_status,
            }
            result["network"] = {
                "request_count": req_count,
                "external_domains": sorted(ext_domains)[:100],
                "failed_request_count": failed_req_count,
                "blocked_ssrf_count": blocked_ssrf_count,
            }
            result["scripts"]["external_script_count"] = len(script_urls)
            result["scripts"]["script_urls"] = script_urls
            result["behaviour"] = {
                "popup_count": popup_count,
                "download_attempt_count": download_count,
                "download_filenames": download_names,
                "console_error_count": console_err_count,
                "page_error_count": page_err_count,
            }
            if timed_out:
                result["status"] = "partial" if result["dom"]["snapshot_captured"] or req_count > 0 else "timed_out"
            elif result["error"] is None:
                result["status"] = "completed"
            elif result["dom"]["snapshot_captured"] or req_count > 0:
                result["status"] = "partial"

            try:
                page.unroute_all(behavior="ignoreErrors")
            except Exception:
                pass
            try:
                context.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass
    except Exception as exc:
        result["error"] = f"Browser failure: {type(exc).__name__}"
        result["status"] = "failed"

    result["duration_ms"] = round((time.monotonic() - t0) * 1000)

    # Enforce hard output cap
    encoded = json.dumps(result)
    if len(encoded.encode("utf-8")) > MAX_OUTPUT_BYTES:
        result["dom"]["rendered_html"] = ""
        result["dom"]["snapshot_captured"] = False
        limitations.append("Rendered HTML dropped to stay within 2 MB evidence output cap.")
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.getenv("SCAN_URL", ""))
    ap.add_argument("--scan-id", default=os.getenv("SCAN_ID", str(uuid.uuid4())))
    ap.add_argument("--allow-private", action="store_true")
    args = ap.parse_args()
    out = scan(args.url, args.scan_id, allow_private=args.allow_private or ALLOW_PRIVATE)
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
