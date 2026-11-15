"""
Contract test for model 1 + the detector (own code).  Run from AIDev with the venv active:

    python check_result_shape.py

It does live lookups (PhishTank, RDAP, page download), so run it on your own PC. It never changes any file.

Part 1  predict.py: the model loads, the validated threshold sits exactly on the detector's warning level (0.7), the
        flag agrees with the score, odd inputs give None or a dict but never an error, the rescaling is monotone.
Part 2  analyze(): every kind of path (list hit, trusted list, with and without use_ai, unknown site with an unreachable
        page, public hosting platform, invalid URL) returns the fields the desktop app and the extension read:
        status, risk_score, has_data, url, source, reasons, and the structured blocks checks / ai1 / ai2 / ai_combined / final
        (UI contract: a score, a status, a list of what was detected, a short explanation, also when a source has no opinion).
Exit code 0 = all checks passed, 1 = at least one FAILED. Lines starting with NOTE or WARN do not fail the test.
"""
from __future__ import annotations

import sys
import time

PROVIDER_IDS = ["blacklist", "feed", "adult", "whitelist", "phishtank", "safebrowsing", "lookalike", "domain_age", "ai1", "ai2"]
STATUSES = {"Malicious", "Suspicious", "Safe", "Unknown", "Restricted"}
CHECK_STATES = {"match", "clear", "unavailable", "not_configured", "skipped", "no_opinion"}
BLOCK_STATES = {"ok", "no_opinion", "skipped"}
GROUPS = {"list", "api", "rule", "ai"}
EFFECTS = {"none", "risk", "trust"}
LEVELS = {"none", "low", "elevated", "high"}


def _text(x) -> bool:
    return isinstance(x, str) and x.strip() != ""


def _number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def shape_problems(r) -> list[str]:
    """Everything that is wrong with one analyze() result (empty list = fine)."""
    if not isinstance(r, dict):
        return ["result is not a dict"]
    p: list[str] = []
    for k in ("status", "risk_score", "has_data", "url", "source", "reasons"):
        if k not in r:
            p.append(f"missing field '{k}'")
    if p:
        return p
    if r["status"] not in STATUSES:
        p.append(f"status '{r['status']}' is not one of {sorted(STATUSES)}")
    if not _number(r["risk_score"]):
        p.append("risk_score is not a number")
    if not isinstance(r["has_data"], bool):
        p.append("has_data is not true/false")
    if not _text(r["source"]):
        p.append("source is empty")
    if not isinstance(r["reasons"], list) or not r["reasons"] or not all(_text(x) for x in r["reasons"]):
        p.append("reasons must be a non-empty list of text lines")
    if r["reasons"] == ["Invalid URL"]:
        return p                                           # an invalid address has no structured blocks (see NOTE in main)

    checks = r.get("checks")
    if not isinstance(checks, list):
        p.append("missing list 'checks'")
    else:
        if [c.get("id") for c in checks if isinstance(c, dict)] != PROVIDER_IDS:
            p.append(f"checks must hold exactly these sources in this order: {PROVIDER_IDS}")
        for c in checks:
            if not isinstance(c, dict):
                p.append("a check is not a dict")
                continue
            cid = c.get("id")
            if not _text(c.get("name")):
                p.append(f"check '{cid}': empty name")
            if c.get("group") not in GROUPS:
                p.append(f"check '{cid}': group '{c.get('group')}' unknown")
            if c.get("state") not in CHECK_STATES:
                p.append(f"check '{cid}': state '{c.get('state')}' unknown")
            if not _text(c.get("detail")):
                p.append(f"check '{cid}': empty detail (the screen must always say what happened)")
            if c.get("effect") not in EFFECTS:
                p.append(f"check '{cid}': effect '{c.get('effect')}' unknown")
            if c.get("state") == "match" and c.get("effect") == "none":
                p.append(f"check '{cid}': a match must say whether it is risk or trust")

    for name in ("ai1", "ai2", "ai_combined"):
        b = r.get(name)
        if not isinstance(b, dict):
            p.append(f"missing block '{name}'")
            continue
        if not _text(b.get("name")):
            p.append(f"{name}: empty name")
        if b.get("state") not in BLOCK_STATES:
            p.append(f"{name}: state '{b.get('state')}' unknown")
        if not _text(b.get("description")):
            p.append(f"{name}: empty description")
        if b.get("level") not in LEVELS:
            p.append(f"{name}: level '{b.get('level')}' unknown")
        pc = b.get("percent")
        if pc is not None and not (_number(pc) and 0 <= pc <= 100):
            p.append(f"{name}: percent {pc!r} is not None or 0..100")
        if b.get("state") == "ok" and name == "ai1" and pc is None:
            p.append("ai1: state ok but no percent")
    if isinstance(r.get("ai2"), dict):
        for k in ("categories", "signals"):
            if not isinstance(r["ai2"].get(k), list):
                p.append(f"ai2: '{k}' must be a list")

    fin = r.get("final")
    if not isinstance(fin, dict):
        p.append("missing block 'final'")
    else:
        if fin.get("status") != r["status"]:
            p.append(f"final.status '{fin.get('status')}' differs from status '{r['status']}'")
        if not _text(fin.get("summary")):
            p.append("final.summary is empty")
        if not _text(fin.get("method")):
            p.append("final.method is empty")
        if not isinstance(fin.get("notes"), list):
            p.append("final.notes must be a list")
        for part in ("list_api", "ai"):
            if not isinstance(fin.get(part), dict) or not _text(fin[part].get("text")):
                p.append(f"final.{part}.text is empty")
        if r["has_data"] != (fin.get("score") is not None):
            p.append("has_data and final.score disagree (score None must mean has_data false)")
        elif r["has_data"] and _number(fin.get("score")) and abs(float(r["risk_score"]) - float(fin["score"])) > 1e-9:
            p.append(f"risk_score {r['risk_score']} differs from final.score {fin['score']}")

    if isinstance(checks, list) and isinstance(r.get("ai1"), dict):
        c1 = next((c for c in checks if isinstance(c, dict) and c.get("id") == "ai1"), None)
        if c1 is not None:
            if r["ai1"].get("state") == "no_opinion" and c1.get("state") != "no_opinion":
                p.append("ai1 says no opinion but its check says something else")
            if r["ai1"].get("state") == "skipped" and c1.get("state") != "skipped":
                p.append("ai1 block skipped but its check was not")
            if r["ai1"].get("state") == "ok" and c1.get("state") not in ("match", "clear"):
                p.append("ai1 has a result but its check is not match / clear")
    return p


# ---------------------------------------------------------------------------------------------------------------------
class Report:
    def __init__(self) -> None:
        self.failed = 0
        self.passed = 0

    def ok(self, msg: str) -> None:
        self.passed += 1
        print(f"  PASS  {msg}")

    def fail(self, msg: str) -> None:
        self.failed += 1
        print(f"  FAIL  {msg}")

    def check(self, cond: bool, msg: str) -> None:
        (self.ok if cond else self.fail)(msg)


def part1_model(rep: Report, warning_level: float) -> None:
    from aidev.detection import predict as P

    print("\nPart 1: predict.py (model 1)")
    loaded, why = P.status()
    rep.check(loaded, "the model file loads" + ("" if loaded else f" -- {why}"))
    if not loaded:
        return
    rep.check(abs(P.WARNING_LEVEL - warning_level) < 1e-12,
              f"predict.WARNING_LEVEL ({P.WARNING_LEVEL}) equals detector.ML_SUSPICIOUS_PROB ({warning_level})")
    bundle = P._BUNDLE
    thr = bundle.get("threshold")
    print(f"  NOTE  model {bundle.get('version')}; stacked with n-gram: {bundle.get('ngram') is not None}; "
          f"validated threshold (raw): {thr}")
    if thr is not None:
        xs = [0.0, thr / 2, thr * 0.999, thr, thr + (1 - thr) / 2, 1.0]
        ys = [P._rescale(x, thr) for x in xs]
        rep.check(abs(ys[3] - warning_level) < 1e-9, "the validated threshold maps exactly onto the warning level")
        rep.check(all(a <= b + 1e-12 for a, b in zip(ys, ys[1:])) and ys[0] == 0 and abs(ys[-1] - 1) < 1e-9,
                  "the rescaling is monotone and runs from 0 to 1")

    urls = ["https://www.maybank2u.com.my/", "https://github.com/", "http://paypal-secure-login-verify.xyz/account/update",
            "http://192.168.10.5:8080/login.php", "https://xn--pypal-4ve.com/signin", "https://" + "a" * 60 + ".com/" + "b" * 300,
            "https://secure-maybank2u-login.top/"]
    lat, bad = [], []
    for u in urls:
        r = P.predict(u)
        if r is None:
            bad.append(f"{u[:50]}: no result")
            continue
        lat.append(r["latency_ms"])
        for k in ("probability", "risk_score", "model_version", "top_features", "latency_ms"):
            if k not in r:
                bad.append(f"{u[:50]}: missing '{k}'")
        if not (0 <= r["probability"] <= 1):
            bad.append(f"{u[:50]}: probability {r['probability']} outside 0..1")
        if thr is not None:
            for k in ("raw_probability", "threshold", "flagged"):
                if k not in r:
                    bad.append(f"{u[:50]}: missing '{k}'")
            if "flagged" in r and r["flagged"] != (r["probability"] >= warning_level):
                bad.append(f"{u[:50]}: flagged={r['flagged']} but probability {r['probability']:.4f} vs {warning_level}")
        print(f"  NOTE  risk {r['risk_score']:5.1f}  raw {r.get('raw_probability', r['probability']):.4f}  "
              f"flagged {r.get('flagged')}  {u[:70]}")
    rep.check(not bad, "every sample URL gets a complete result and the flag agrees with the score"
              + ("" if not bad else " -- " + "; ".join(bad)))
    for u in ("", "http://", "not a url at all", None):
        try:
            r = P.predict(u)
            rep.check(r is None or isinstance(r, dict), f"predict({u!r}) returns None or a dict")
        except Exception as exc:                                   # predict() promises never to raise
            rep.fail(f"predict({u!r}) raised {type(exc).__name__}: {exc}")
    if lat:
        med = sorted(lat)[len(lat) // 2]
        (print(f"  WARN  median latency {med} ms (above 200 ms: the extension may feel slow)") if med > 200
         else print(f"  NOTE  median latency {med} ms"))
    phishy = [P.predict(u) for u in urls[2:3] + urls[6:7]]
    if all(x and not x.get("flagged") for x in phishy):
        print("  WARN  neither obvious phishing-looking sample was flagged by model 1 alone (not an error by itself)")
    if any(P.predict(u) and P.predict(u).get("flagged") for u in urls[:2]):
        print("  WARN  a well-known benign site was flagged by model 1 alone (the detector's trusted list would still win)")


def part2_detector(rep: Report) -> None:
    from aidev.detection import detector as D

    print("\nPart 2: analyze() (live lookups, may take a few seconds per URL)")
    feed_url = next(iter(sorted(D.FEED_URLS)), None) if D.FEED_URLS else None
    cases = [
        ("trusted list", "https://www.wikipedia.org/", False),
        ("trusted list, use_ai=True", "https://www.wikipedia.org/", True),
        ("unknown site on no list (AI path, page unreachable)", "http://paypal-secure-login-verify.invalid/account/update", False),
        ("public hosting platform", "https://paypal-login-secure.github.io/", False),
        ("invalid address", "http://", False),
    ]
    if feed_url:
        cases.insert(0, ("OpenPhish / URLhaus feed hit", "http://" + feed_url, False))
    else:
        print("  NOTE  the feed list is empty here, so no feed-hit case")
    results = {}
    for label, url, use_ai in cases:
        t0 = time.perf_counter()
        try:
            r = D.analyze(url, use_ai=use_ai)
        except Exception as exc:
            rep.fail(f"{label}: analyze() raised {type(exc).__name__}: {exc}")
            continue
        dt = time.perf_counter() - t0
        results[label] = r
        probs = shape_problems(r)
        rep.check(not probs, f"{label}: all fields present  [{r.get('status')}, risk {r.get('risk_score')}, source {r.get('source')}, {dt:.1f}s]"
                  + ("" if not probs else " -- " + "; ".join(probs)))
        if r.get("reasons") == ["Invalid URL"]:
            print("  NOTE  an invalid address returns no checks / ai / final blocks: the screens must cope with that")
        elif isinstance(r.get("ai1"), dict):
            print(f"  NOTE  AI 1 -> {r['ai1']['state']}, percent {r['ai1']['percent']}: {r['ai1']['description'][:110]}...")
        r2 = D.analyze(url, use_ai=use_ai)                      # second call: may come from the cache, must look the same
        probs2 = shape_problems(r2)
        rep.check(not probs2 and r2.get("status") == r.get("status"), f"{label}: the repeated (cached) answer has the same shape and status"
                  + ("" if not probs2 else " -- " + "; ".join(probs2)))

    a, b = results.get("trusted list"), results.get("trusted list, use_ai=True")
    if a and b:
        rep.check(a["status"] == b["status"], "use_ai=True does not change the verdict of a list decision")
        rep.check(b["ai1"]["state"] in ("ok", "no_opinion"), "use_ai=True on a list hit really runs AI 1 (not 'skipped')")
    u = results.get("unknown site on no list (AI path, page unreachable)")
    if u:
        rep.check(u["ai1"]["state"] == "ok", "an ordinary unknown URL gets an AI 1 result (the model is loaded)")
        rep.check(u["ai2"]["state"] in ("no_opinion", "skipped", "ok"), "an unreachable page gives AI 2 'no opinion' (not a crash)")
        rep.check(u["status"] != "Safe", "an unreachable, unknown, phishing-looking site is never called Safe")
    s = results.get("public hosting platform")
    if s:
        rep.check(s["ai2"]["state"] == "skipped", "a public hosting platform skips the page model (it was not trained on them)")


def main() -> int:
    rep = Report()
    try:
        from aidev.detection import detector as D
        warning = D.ML_SUSPICIOUS_PROB
    except Exception as exc:
        print(f"FAIL  could not import aidev.detection.detector: {type(exc).__name__}: {exc}")
        return 1
    part1_model(rep, warning)
    part2_detector(rep)
    print(f"\n{rep.passed} passed, {rep.failed} failed")
    return 1 if rep.failed else 0


if __name__ == "__main__":
    sys.exit(main())
