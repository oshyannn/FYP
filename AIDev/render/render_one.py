"""
Single-URL entrypoint, run INSIDE the Docker sandbox by aidev/detection/render_rescore.py:
    python /app/render_one.py URL
Prints ONE JSON object as the last line of stdout. Nothing else is written.
"""
import json
import sys

from playwright.sync_api import sync_playwright

import render_pages as rp

CHROMIUM_ARGS = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-extensions"]


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else ""
    if not rp.scheme_ok(url):
        print(json.dumps({"ok": False, "error": "scheme refused", "html": "", "redirects": [],
                          "final_url": url, "status": ""}))
        return 0
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=CHROMIUM_ARGS)
        try:
            res = rp.render_one(browser, url)
        finally:
            browser.close()
    status = res["status"]
    ok = bool(res["html"]) and status != "" and int(status) < 400
    print(json.dumps({"ok": ok, "error": res["error"], "final_url": res["final_url"],
                      "status": status, "redirects": res["redirects"], "html": res["html"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
