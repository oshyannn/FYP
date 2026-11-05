"""Optional AI check for URLs that a list already decided (safe to run more than once).

Run from the Backend folder:   python -m scripts.enable_optional_ai

Today a URL on the blacklist / feed / adult list / whitelist / institutional endings is answered at once and the two AI models
are "Not run". With this change the person can tick "Also run the AI models" in the URL Scanner:
  - the list result STILL decides the final status (a blacklisted site stays Malicious, a trusted one stays Safe);
  - AI 1 and AI 2 run as well, and their result is shown in the detail screen next to the list result;
  - a note says when the AI models disagree with the list;
  - if the box is not ticked, nothing changes at all.

It edits two files and either changes both or none (a backup of each is kept as *.before_optional_ai.bak):
  AIDev/aidev/detection/detector.py        analyze(url, use_ai=False), and the list path runs the models when asked
  Backend/web/controllers/scans.py         POST /api/scans accepts  {"url": "...", "use_ai": true}
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "AIDev" / "aidev" / "detection" / "detector.py"
SCANS = ROOT / "Backend" / "web" / "controllers" / "scans.py"

DETECTOR_MARK = "_use_ai_on_lists"
SCANS_MARK = "use_ai=data.get("

DETECTOR_EDITS = [
    # 1. import
    ('''import logging
import os
import time
''', '''import contextvars
import logging
import os
import time
'''),
    # 2. analyze() takes the switch and passes it down without touching the seven list branches
    ('''def analyze(raw_url: str) -> dict:
    """Verdict for one URL. Slow-path verdicts are cached, so the same page is not downloaded and looked up again."""
    key = normalize(raw_url)
    now = time.time()
    hit = _result_cache.get(key)
    if hit and hit[0] > now:
        return {**hit[1], "url": raw_url, "cached": True}
    result = _analyze(raw_url)
''', '''# Optional: run the two AI models even when a local list already decided the URL (see _ai_for_listed). Off unless asked for.
_use_ai_on_lists: contextvars.ContextVar = contextvars.ContextVar("use_ai_on_lists", default=False)


def analyze(raw_url: str, use_ai: bool = False) -> dict:
    """Verdict for one URL. Slow-path verdicts are cached, so the same page is not downloaded and looked up again.
    use_ai=True also runs AI 1 and AI 2 on a URL that a list (blacklist, whitelist ...) has already decided: the list result stays
    the final result and the AI result is added for information. A URL no list knows is always analysed with the AI models."""
    key = normalize(raw_url)
    now = time.time()
    hit = _result_cache.get(key)
    if hit and hit[0] > now:
        return {**hit[1], "url": raw_url, "cached": True}
    token = _use_ai_on_lists.set(bool(use_ai))
    try:
        result = _analyze(raw_url)
    finally:
        _use_ai_on_lists.reset(token)
'''),
    # 3. the list path: run the models when asked, otherwise exactly as before
    ('''def _by_list(url, status, score, source, reasons, ck: _Checks, why: str, category: str | None = None) -> dict:
    """A result decided by a local list: the APIs and the AI models were not needed, and are listed as skipped."""
    ck.skip_rest(why)
    extra = _ai_off(why)
    checks = ck.as_list()
    extra["checks"] = checks
    extra["final"] = _final_block(status, score, checks, score, extra["ai_combined"], [])
''', '''def _ai_for_listed(url: str, status: str, ck: _Checks) -> tuple[dict, list[str]]:
    """Optional: run AI 1 and AI 2 on a URL that a local list has already decided. Returns the AI blocks and the notes for the result.
    The list result stays the final result; a note says when the AI models disagree with it."""
    norm = normalize(url)
    host = get_host(norm)
    shared = is_shared(host)
    ml = ml_predict(f"https://{host}/" if shared else norm)
    ml_score = None if ml is None else _ml_to_score(ml["probability"])
    content = content_score = download_score = None
    skip = None
    if shared:
        skip = "Skipped: this is a public hosting platform, and the page model was not trained on such pages."
    elif not predict_content.enabled():
        skip = "Switched off (CONTENT_CHECK=0)."
    else:
        content = predict_content.predict(norm)
        if content is not None:
            if content.get("download") and content.get("download_kind") != "direct":
                download_score = DOWNLOAD_AUTO_SCORE
            if content.get("probability") is not None:
                content_score = _content_to_score(content["probability"])
    ai2_score = max([x for x in (content_score, download_score) if x is not None], default=None)
    ai1, ai2, comb = _ai1_block(ml, ml_score, shared), _ai2_block(content, ai2_score, skip), _ai_combined(ml_score, ai2_score)
    # everything computed: only now record it, so a failure above leaves the result exactly as it was without the option
    ck.add("ai1", "no_opinion" if ml_score is None else "match" if ml_score >= THRESHOLD_SUSPICIOUS else "clear",
           f"Phishing probability {ai1['percent']}%" if ml is not None else f"No opinion: {_ai1_why()}",
           ml_score, "risk" if ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS else "none")
    if ai2["state"] == "ok":
        hot = [c for c in ai2["categories"] if c["triggered"]]
        hit = ai2_score is not None and ai2_score >= THRESHOLD_SUSPICIOUS
        ck.add("ai2", "match" if hit else "clear",
               (f"Phishing probability {ai2['percent']}%" if ai2["percent"] is not None else "Page read, no probability from the model")
               + (" · " + ", ".join(f"{c['label']} {c['percent']}%" for c in hot) if hot else ""),
               ai2_score, "risk" if hit else "none")
    else:
        ck.add("ai2", ai2["state"], ai2["description"].replace(AI2_BASE + " ", ""))
    notes = ["The optional AI check was switched on: the AI models ran even though a list decided this URL. "
             "The list result stays the final result; the AI result is shown for information."]
    s = comb.get("score")
    if status == "Safe" and s is not None and s >= THRESHOLD_SUSPICIOUS:
        notes.append("The AI models disagree with the trusted list: they see warning signs on this site. Treat it with care.")
    elif status in ("Malicious", "Restricted") and s is not None and s < THRESHOLD_SUSPICIOUS:
        notes.append("The AI models see no strong warning sign, but the list result stays.")
    elif s is None:
        notes.append("Neither AI model could score this site.")
    return {"ai1": ai1, "ai2": ai2, "ai_combined": comb}, notes


def _by_list(url, status, score, source, reasons, ck: _Checks, why: str, category: str | None = None) -> dict:
    """A result decided by a local list: the APIs and the AI models were not needed, and are listed as skipped.
    With the optional switch on (analyze(..., use_ai=True)) the two AI models still run, for information only."""
    notes: list[str] = []
    ai_on = _use_ai_on_lists.get()
    if ai_on:
        try:
            extra, notes = _ai_for_listed(url, status, ck)
        except Exception:                                  # the option must never break a list result
            log.exception("optional AI check failed")
            ai_on = False
    ck.skip_rest(why)
    if not ai_on:
        extra = _ai_off(why)
    checks = ck.as_list()
    extra["checks"] = checks
    extra["final"] = _final_block(status, score, checks, score, extra["ai_combined"], notes)
    if ai_on:
        extra["ai_optional"] = True
'''),
]

SCANS_EDITS = [
    ('''        result = analyze(url)
''', '''        result = analyze(url, use_ai=data.get("use_ai") is True)   # optional: also run the AI models when a list already decided the URL
'''),
]

FILES = [("detector.py", DETECTOR, DETECTOR_MARK, DETECTOR_EDITS), ("scans.py", SCANS, SCANS_MARK, SCANS_EDITS)]


def main() -> int:
    plan = []                                              # (path, new_text) for every file that still needs the change
    for name, path, mark, edits in FILES:
        if not path.exists():
            print(f"Cannot find {path}")
            return 1
        text = path.read_text(encoding="utf-8")
        if mark in text:
            print(f"{name}: already changed.")
            continue
        bad = [i for i, (old, _new) in enumerate(edits, 1) if text.count(old) != 1]
        if bad:
            print(f"Nothing was changed. {name}: these pieces were not found exactly once (the file was edited there): "
                  + ", ".join(f"edit {i}" for i in bad) + ".\nSend the current text of those places and they can be adjusted.")
            return 1
        for old, new in edits:
            text = text.replace(old, new)
        plan.append((path, text))
    if not plan:
        print("Nothing to do.")
        return 0
    for path, text in plan:                                # all checks passed: back up, then write
        shutil.copyfile(path, path.with_name(path.name + ".before_optional_ai.bak"))
        path.write_text(text, encoding="utf-8")
        print(f"Changed {path.name} (backup: {path.name}.before_optional_ai.bak)")
    print("Restart the backend: python app.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
