"""
See every layer of the detector for any URL, whitelisted or not, each with a short reason.

    python testai.py https://some-small-site.com
    python testai.py --file urls.txt        # one URL per line; add ",1" (phishing) or ",0" (benign) to get an accuracy summary
    python testai.py                        # no arguments: type URLs, blank line to quit
    python testai.py URL --json             # one JSON object per URL
    python testai.py URL --verbose          # also show backend log lines (why a model gave no opinion)

Per URL:
  [1] AI 1  URL-text model        called directly (ignores the whitelist)
  [2] AI 2  page-content model    called directly (ignores the whitelist)
  [3] AI 1+2 together             rule: both >= threshold -> flagged; one alone is not trusted (see combine())
  [4] API / lists                 detector.analyze() with BOTH AI models switched off: whitelist, blacklist,
                                  PhishTank, Safe Browsing, look-alike, shared-host rule...
  [5] FINAL (AI + API)            detector.analyze() as the real system runs it
With labelled URLs it ends with how many phishing pages each layer caught and how many benign ones it wrongly flagged.
Note: each URL makes detector.analyze() run twice, so PhishTank is asked twice; --pause (default 3 s) keeps it below its limit.
"""
from __future__ import annotations

import argparse
import json
import logging
import time
import warnings
from urllib.parse import urlsplit

warnings.filterwarnings("ignore", message="X does not have valid feature names")

import detector
import pagefetch
import predict as _predict_mod
import predict_content as pc
from common import is_shared

ML1 = _predict_mod.predict          # original callables, kept so they can be swapped out and back
ML2 = pc.predict
FLAG_STATUS = ("Suspicious", "Malicious")


def _none(*a, **k):
    return None


def _clear() -> None:
    pc._cache.clear()
    try:
        detector._result_cache.clear()
    except Exception:
        pass


def band(p, thr: float) -> str:
    return "no opinion" if p is None else "HIGH" if p >= thr else "raised" if p >= 0.4 else "low"


def pct(p) -> str:
    return f"{p:.0%}" if isinstance(p, (int, float)) else "no opinion"


def run_ai1(url: str, thr: float) -> dict:
    m = ML1(url)
    d: dict = {"p": m["probability"] if m else None}
    if m and isinstance(m.get("top_features"), list):
        try:
            d["top"] = [f"{x['name']}={x['value']}" if isinstance(x, dict) else f"{x[0]}={x[1]}" for x in m["top_features"][:3]]
        except Exception:
            pass
    u = urlsplit(url)
    root = f"{u.scheme}://{u.netloc}/"
    d["shared"] = bool(is_shared(u.hostname or ""))
    if root.rstrip("/") != url.rstrip("/"):
        mh = ML1(root)
        d["p_host"] = mh["probability"] if mh else None
    d["used"] = d["p_host"] if d["shared"] and d.get("p_host") is not None else d["p"]
    d["flag"] = None if d["used"] is None else d["used"] >= thr
    if d["used"] is None:
        d["why"] = "model missing or could not score this address"
    else:
        d["why"] = (f"scores the address text only (not the page): {pct(d['used'])} is {band(d['used'], thr)}. "
                    + ("Shared-hosting site, so the host-only score is used because paths are random IDs. " if d["shared"] and d.get("p_host") is not None else "")
                    + (("Main features (global, not per-URL): " + ", ".join(d["top"])) if d.get("top") else ""))
    return d


def run_ai2(url: str, thr: float) -> dict:
    if not pc.available():
        return {"p": None, "flag": None, "why": "model not loaded (model_content.joblib missing, feature-version mismatch, or CONTENT_CHECK=0)", "signals": []}
    c = pc.predict(url)
    if c and c.get("probability") is not None:
        p = c["probability"]
        sig = c.get("signals", [])
        why = (f"{pct(p)} is {band(p, thr)}. Warning signs found: " + "; ".join(sig)) if sig else \
              f"{pct(p)} is {band(p, thr)}. No individual warning signs; the score comes from overall page statistics."
        fu = c.get("final_url") or ""
        h0 = (urlsplit(url).hostname or "").removeprefix("www.")
        h1 = (urlsplit(fu).hostname or "").removeprefix("www.")
        if fu and h1 and h0 != h1:
            why += f"  NOTE: the address redirected to {fu[:60]}, so this score describes THAT page, not the original site."
        return {"p": p, "flag": p >= thr, "why": why, "signals": sig, "final_url": fu}
    pg = pagefetch.fetch(url)
    why = pg.error or ("page is almost empty: built by JavaScript" if len(pg.html) < 200 else "unknown, run with --verbose")
    if pg.url.rstrip("/") != url.rstrip("/"):
        why += f" (ended at {pg.url[:70]})"
    return {"p": None, "flag": None, "why": "no opinion: " + why, "signals": []}


def combine(a1: dict, a2: dict, thr: float) -> dict:
    p1, p2 = a1["used"], a2["p"]
    if p1 is None and p2 is None:
        return {"flag": None, "verdict": "no opinion", "why": "neither model could score it"}
    if p2 is None:
        f = p1 >= thr
        return {"flag": f, "verdict": "URL model only: " + ("HIGH" if f else "no strong signal"),
                "why": "the page model has no opinion, so the URL model decides alone (the detector caps this at Suspicious)"}
    if p1 is None:
        f = p2 >= thr
        return {"flag": f, "verdict": "page model only: " + ("HIGH" if f else "no strong signal"), "why": "the URL model has no opinion"}
    h1, h2 = p1 >= thr, p2 >= thr
    if h1 and h2:
        return {"flag": True, "verdict": "SUSPICIOUS: both models agree", "why": f"URL {pct(p1)} and page {pct(p2)} are both >= {thr:.0%}"}
    if h1 or h2:
        return {"flag": False, "verdict": "weak: only one model flags it",
                "why": f"only the {'URL' if h1 else 'page'} model is >= {thr:.0%} ({pct(p1)} / {pct(p2)}); one model alone is not trusted"}
    return {"flag": False, "verdict": "no strong signal", "why": f"URL {pct(p1)} and page {pct(p2)} are both below {thr:.0%}"}


def run_api(url: str) -> dict:
    """detector.analyze with both AI models off. Swaps the module attributes AND any name inside detector bound to them."""
    swaps = []

    def swap(obj, name):
        swaps.append((obj, name, getattr(obj, name)))
        setattr(obj, name, _none)

    swap(_predict_mod, "predict")
    swap(pc, "predict")
    for name, val in list(vars(detector).items()):
        if val is ML1 or val is ML2:
            swap(detector, name)
    try:
        _clear()
        r = detector.analyze(url)
    finally:
        for obj, name, val in reversed(swaps):
            setattr(obj, name, val)
        _clear()
    out = pack(r)
    src = str(r.get("source")).lower()
    # "Page content could not be read" is expected here (the AI is switched off); a probability or a model source is not
    if "probability" in " ".join(map(str, r.get("reasons", []))).lower() or "model" in src or "content" in src:
        out["warn"] = "this lists-only result still mentions an AI model: detector.py calls the models in a way this swap missed"
    return out


def pack(r: dict) -> dict:
    return {"status": r.get("status"), "score": r.get("risk_score"), "source": r.get("source"),
            "reasons": list(r.get("reasons", [])), "flag": r.get("status") in FLAG_STATUS}


def check(url: str, thr: float, label) -> dict:
    o: dict = {"url": url, "label": label}
    try:
        _clear()
        o["api"] = run_api(url)
        o["ai1"] = run_ai1(url, thr)
        o["ai2"] = run_ai2(url, thr)
        o["combo"] = combine(o["ai1"], o["ai2"], thr)
        o["final"] = pack(detector.analyze(url))          # not cleared: reuses the page already downloaded for AI 2
    except Exception as exc:
        o["error"] = f"{type(exc).__name__}: {exc}"
    return o


def mark(flag, label) -> str:
    if label is None:
        return ""
    if flag is None:
        return "  (no opinion)"
    return "  OK" if flag == bool(label) else "  MISSED" if label else "  FALSE ALARM"


def show(o: dict, thr: float) -> None:
    print("=" * 78)
    lab = o["label"]
    print(o["url"] + ("" if lab is None else f"   [truth: {'PHISHING' if lab else 'benign'}]"))
    if "error" in o:
        print("  ERROR:", o["error"])
        return
    a1, a2, c, api, fin = o["ai1"], o["ai2"], o["combo"], o["api"], o["final"]
    print(f"[1] AI 1 URL-text model     : {pct(a1['used'])}  {band(a1['used'], thr)}{mark(a1['flag'], lab)}")
    print("      why:", a1["why"])
    print(f"[2] AI 2 page-content model : {pct(a2['p'])}  {band(a2['p'], thr)}{mark(a2['flag'], lab)}")
    print("      why:", a2["why"])
    print(f"[3] AI 1+2 together         : {c['verdict']}{mark(c['flag'], lab)}")
    print("      why:", c["why"])
    print(f"[4] API / lists (no AI)     : {api['status']}  score {api['score']}  [{api['source']}]{mark(api['flag'], lab)}")
    for x in api["reasons"]:
        print("      -", x)
    if api.get("warn"):
        print("      !", api["warn"])
    print(f"[5] FINAL (AI + API)        : {fin['status']}  score {fin['score']}  [{fin['source']}]{mark(fin['flag'], lab)}")
    for x in fin["reasons"]:
        print("      -", x)


def summary(rows: list[dict], thr: float) -> None:
    lab = [r for r in rows if r.get("label") is not None and "error" not in r]
    if not lab:
        return
    n1 = sum(r["label"] for r in lab)
    print("=" * 78)
    print(f"ACCURACY on {len(lab)} labelled URLs ({n1} phishing, {len(lab) - n1} benign). Flagged = score >= {thr:.0%}, or status Suspicious/Malicious")
    cols = [("[1] AI 1 URL", lambda r: r["ai1"]["flag"]), ("[2] AI 2 page", lambda r: r["ai2"]["flag"]),
            ("[3] AI 1+2", lambda r: r["combo"]["flag"]), ("[4] API/lists", lambda r: r["api"]["flag"]),
            ("[5] FINAL", lambda r: r["final"]["flag"])]
    for name, f in cols:
        P = [r for r in lab if r["label"] == 1 and f(r) is not None]
        N = [r for r in lab if r["label"] == 0 and f(r) is not None]
        none = sum(1 for r in lab if f(r) is None)
        print(f"  {name:<14} caught {sum(f(r) for r in P)}/{len(P)} phishing   wrongly flagged {sum(f(r) for r in N)}/{len(N)} benign   no opinion {none}")
    print("  Under ~100 URLs this is a rough indication only. Use URLs that were NOT in the training data, and a mix of both classes.")


def parse(raw: str):
    raw = raw.strip()
    head, _, tail = raw.rpartition(",")
    if head and tail.strip() in ("0", "1"):
        return norm(head), int(tail)
    return norm(raw), None


def norm(u: str) -> str:
    u = u.strip()
    return u if u.lower().startswith(("http://", "https://")) else "https://" + u


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", nargs="*", help="URL, optionally 'URL,1' (phishing) or 'URL,0' (benign)")
    ap.add_argument("--file", help="text file, one URL per line, optional ',0' / ',1' label")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--threshold", type=float, default=0.7, help="AI score counted as flagged (default 0.7)")
    ap.add_argument("--pause", type=float, default=3.0, help="seconds between URLs (PhishTank limit)")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    if a.verbose:
        logging.basicConfig(level=logging.INFO)
    items = [parse(u) for u in a.urls]
    if a.file:
        items += [parse(l) for l in open(a.file, encoding="utf-8", errors="ignore") if l.strip() and not l.strip().startswith("#")]
    rows: list[dict] = []

    def run(u, lab) -> None:
        o = check(u, a.threshold, lab)
        rows.append(o)
        print(json.dumps(o, default=str, ensure_ascii=False)) if a.json else show(o, a.threshold)

    if items:
        for i, (u, lab) in enumerate(items):
            if i:
                time.sleep(a.pause)
            run(u, lab)
    else:
        try:
            while True:
                s = input("URL (blank to quit): ").strip()
                if not s:
                    break
                run(*parse(s))
        except (EOFError, KeyboardInterrupt):
            pass
    if not a.json:
        summary(rows, a.threshold)
