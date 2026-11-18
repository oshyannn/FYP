"""
Headless rendering for model 2. Run ONLY inside the Docker sandbox (see README_render.md).

Input : CSV with columns  url,label,source,group   (one row per page to render)
Output: OUT/pages.csv + OUT/html/*.html.gz   (same layout as data/pages/, so train_content2 can read it)
        OUT/render_log.csv                    (every URL, including the failures)

Rules built into the code (the Docker limits are the real boundary; these are extra):
  * only http/https URLs; file:, ftp: and other schemes are refused, also when reached by redirect
  * a fresh browser context per page: no cookies, no storage, no history carried between pages
  * downloads refused, dialogs dismissed, popups closed, service workers blocked
  * no clicks, no form filling: the page is loaded, we wait a little, and the DOM is read
  * hard timeout per page; the run stops after MAX_FAIL_RUN failures in a row
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}
IN_PAGE_SCHEMES = ("data:", "blob:", "about:")   # created by the page itself, not fetched from the network
NAV_TIMEOUT_MS = 20_000
SETTLE_MS = 1_500
MAX_HTML_CHARS = 5_000_000
MAX_FAIL_RUN = 25
PAGE_FIELDS = ["url", "label", "source", "group", "final_url", "status", "tls_invalid", "redirects", "html_file", "fetched_at"]
LOG_FIELDS = ["url", "ok", "error", "final_url", "status"]


def scheme_ok(url: str) -> bool:
    return urlsplit(url).scheme.lower() in ALLOWED_SCHEMES


def redirect_chain(request) -> list[str]:
    """Earlier URLs of a redirect chain, newest first. `request` is a Playwright Request (or None)."""
    out = []
    r = request
    while r is not None and r.redirected_from is not None:
        r = r.redirected_from
        out.append(r.url)
    return out


def page_file_name(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest() + ".html.gz"


def _route_guard(route):
    """Let http/https and in-page resources through; abort everything else (file:, ftp:, ...)."""
    url = route.request.url
    if scheme_ok(url) or url.startswith(IN_PAGE_SCHEMES):
        route.continue_()
    else:
        route.abort()


def render_one(browser, url: str) -> dict:
    """Load one page in a fresh context and return its DOM after a short settle time."""
    ctx = browser.new_context(accept_downloads=False, service_workers="block", ignore_https_errors=False,
                              viewport={"width": 1280, "height": 800}, java_script_enabled=True)
    ctx.route("**/*", _route_guard)
    page = ctx.new_page()
    page.on("dialog", lambda d: d.dismiss())
    page.on("popup", lambda p: p.close())
    res = {"final_url": url, "status": "", "html": "", "redirects": [], "error": ""}
    try:
        resp = page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
        page.wait_for_timeout(SETTLE_MS)
        res["final_url"] = page.url
        if resp is not None:
            res["status"] = resp.status
            res["redirects"] = redirect_chain(resp.request)
        res["html"] = page.content()[:MAX_HTML_CHARS]
    except Exception as exc:                      # timeouts, DNS errors, refused redirects, ...
        res["error"] = type(exc).__name__
    finally:
        ctx.close()
    return res


def read_input(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            if scheme_ok(r["url"]):
                rows.append({"url": r["url"], "label": int(r["label"]), "source": r.get("source", ""),
                             "group": r.get("group", "")})
    return rows


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--limit", type=int, default=0, help="render only the first N rows (0 = all)")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds to wait between pages")
    a = ap.parse_args(argv)

    from playwright.sync_api import sync_playwright   # imported here so the helpers can be tested without it

    rows = read_input(a.input)
    if a.limit:
        rows = rows[: a.limit]
    (a.out / "html").mkdir(parents=True, exist_ok=True)
    ok = 0
    fail_run = 0
    with sync_playwright() as p, \
            (a.out / "pages.csv").open("w", newline="", encoding="utf-8") as fp, \
            (a.out / "render_log.csv").open("w", newline="", encoding="utf-8") as fl:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
                                                         "--disable-extensions"])
        wp = csv.DictWriter(fp, fieldnames=PAGE_FIELDS)
        wl = csv.DictWriter(fl, fieldnames=LOG_FIELDS)
        wp.writeheader()
        wl.writeheader()
        for i, r in enumerate(rows, 1):
            res = render_one(browser, r["url"])
            good = bool(res["html"])
            wl.writerow({"url": r["url"], "ok": int(good), "error": res["error"], "final_url": res["final_url"],
                         "status": res["status"]})
            if good:
                name = page_file_name(r["url"])
                with gzip.open(a.out / "html" / name, "wt", encoding="utf-8") as g:
                    g.write(res["html"])
                wp.writerow({"url": r["url"], "label": r["label"], "source": r["source"], "group": r["group"],
                             "final_url": res["final_url"], "status": res["status"],
                             "tls_invalid": 0,            # NOT measured here: see README (copy from the static run)
                             "redirects": "|".join(res["redirects"]), "html_file": name,
                             "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
                ok += 1
                fail_run = 0
            else:
                fail_run += 1
            if i % 50 == 0:
                print(f"  {i}/{len(rows)} done, rendered ok {ok}", flush=True)
            if fail_run >= MAX_FAIL_RUN:
                print(f"stopped: {MAX_FAIL_RUN} failures in a row (check network / Docker DNS)", file=sys.stderr)
                break
            time.sleep(a.delay)
        browser.close()
    print(f"rendered ok {ok} of {len(rows)} rows -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
