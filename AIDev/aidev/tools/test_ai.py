"""
Check URLs of your choice and see, side by side, what each part says.

    python -m aidev.tools.test_ai https://some-small-site.com https://another.org
    python -m aidev.tools.test_ai --file urls.txt            # one URL per line (a trailing ",0" / ",1" label is ignored)
    python -m aidev.tools.test_ai                            # no arguments: type URLs one by one, blank line to quit
    python -m aidev.tools.test_ai URL --json                 # one JSON object per URL, including the raw detector result
                                                 # (shows which fields the API really returns)

For every URL it prints:
  AI 1  : URL-text model, called directly (ignores the whitelist)
  AI 2  : page-content model, called directly (ignores the whitelist)
  FINAL : detector.analyze(), i.e. what the system really decides, and WHICH SOURCE decided it
So a whitelisted site shows both AI scores for information, but the FINAL line says the whitelist decided.
Real URLs only: nothing is faked and the live safety rules of pagefetch are unchanged.
"""
from __future__ import annotations

import argparse
import json
import logging
import time
import warnings
from urllib.parse import urlsplit

warnings.filterwarnings("ignore", message="X does not have valid feature names")

from aidev.detection import detector
from aidev.detection import predict_content
from aidev.core.common import is_shared
from aidev.detection.predict import predict as ml1


def pct(p) -> str:
    return f"{p:.0%}" if isinstance(p, (int, float)) else "no opinion"


def decided_by(src: str) -> str:
    s = (src or "").lower()
    if any(w in s for w in ("whitelist", "trusted", "allow")):
        return "WHITELIST / trusted list (the AI scores above are for information only)"
    if any(w in s for w in ("blacklist", "feed", "phishtank", "safe browsing", "safebrowsing")):
        return "blacklist / reputation source"
    if any(w in s for w in ("model", "content", "lookalike", "look-alike", "shared", "adult")):
        return "AI model and/or rules"
    return "other, see the source name above"


def check(url: str) -> dict:
    predict_content._cache.clear()
    try:
        detector._result_cache.clear()
    except Exception:
        pass
    out: dict = {"url": url}
    try:
        m1 = ml1(url)
        out["ai1"] = m1["probability"] if m1 else None
        p = urlsplit(url)
        root = f"{p.scheme}://{p.netloc}/"
        if root != url and root != url + "/":
            mh = ml1(root)
            out["ai1_host_only"] = mh["probability"] if mh else None
            out["shared_host"] = bool(is_shared(p.hostname or ""))
        c = predict_content.predict(url)                 # not cleared again: detector.analyze reuses this same fetch
        out["ai2"] = c.get("probability") if c else None
        out["ai2_signals"] = c.get("signals", []) if c else []
        out["ai2_download"] = c.get("download") if c else None
        r = detector.analyze(url)
        out["final"] = {"status": r.get("status"), "risk_score": r.get("risk_score"), "source": r.get("source"),
                        "reasons": r.get("reasons", [])}
        out["decided_by"] = decided_by(str(r.get("source")))
        out["detector_raw"] = r
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def show(o: dict) -> None:
    print("=" * 78)
    print(o["url"])
    if "error" in o:
        print("  ERROR:", o["error"])
        return
    print("  AI 1 (URL text)      :", pct(o.get("ai1")))
    if "ai1_host_only" in o:
        print("  AI 1 (host only)     :", pct(o["ai1_host_only"]),
              " <- USED: this is a shared-hosting site (paths are random IDs)" if o.get("shared_host")
              else " <- for comparison only: not a shared-hosting site, the full-URL score is used")
    print("  AI 2 (page content)  :", pct(o.get("ai2")) if o.get("ai2") is not None else "no opinion (page unreadable, JavaScript-only, or model missing)")
    for s in o.get("ai2_signals", []):
        print("      signal:", s)
    if o.get("ai2_download"):
        print("      download:", o["ai2_download"])
    f = o["final"]
    print(f"  FINAL: {f['status']}  score {f['risk_score']}  source [{f['source']}]")
    print("  DECIDED BY:", o["decided_by"])
    for x in f["reasons"]:
        print("      -", x)


def read_urls(path: str) -> list[str]:
    out = []
    for raw in open(path, encoding="utf-8", errors="ignore"):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        head, _, tail = raw.rpartition(",")
        out.append(head.strip() if head and tail.strip() in ("0", "1") else raw)
    return out


def norm(u: str) -> str:
    u = u.strip()
    return u if u.lower().startswith(("http://", "https://")) else "https://" + u


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", nargs="*")
    ap.add_argument("--file", help="text file with one URL per line")
    ap.add_argument("--json", action="store_true", help="print one JSON object per URL")
    ap.add_argument("--verbose", action="store_true", help="show the backend log lines (why a model gave no opinion)")
    ap.add_argument("--pause", type=float, default=2.0, help="seconds between URLs (PhishTank rate limit, default 2)")
    a = ap.parse_args()
    if a.verbose:
        logging.basicConfig(level=logging.INFO)
    urls = [norm(u) for u in a.urls] + [norm(u) for u in (read_urls(a.file) if a.file else [])]
    if not a.json:
        print("AI 2 model available:", predict_content.available())

    def run(u: str) -> None:
        o = check(u)
        print(json.dumps(o, default=str, ensure_ascii=False)) if a.json else show(o)

    if urls:
        for i, u in enumerate(urls):
            if i:
                time.sleep(a.pause)
            run(u)
    else:
        try:
            while True:
                u = input("URL (blank to quit): ").strip()
                if not u:
                    break
                run(norm(u))
        except (EOFError, KeyboardInterrupt):
            pass
