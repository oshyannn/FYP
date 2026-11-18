"""Score HTML that is already in hand with the saved content model. Offline: no fetch, no Supabase, no page code is run.

    from aidev.samples.ai2.score_html import score_html
    score_html(html_text, "https://example.test/")
"""
from __future__ import annotations

import joblib

from aidev.core.common import CONTENT_MODEL_PATH
from aidev.detection import content_features as cf
from aidev.detection.predict_content import signals

MIN_CHARS = 200          # same rule as predict_content: shorter pages are not scored
_bundle = None


def _load() -> dict:
    global _bundle
    if _bundle is None:
        b = joblib.load(CONTENT_MODEL_PATH)
        if b.get("feature_version") != cf.CONTENT_FEATURE_VERSION:
            raise ValueError("model was trained with another feature version; run train_content2 again")
        b["model"].n_jobs = 1
        _bundle = b
    return _bundle


def model_status() -> dict:
    try:
        b = _load()
        return {"loaded": True, "version": b.get("version")}
    except Exception as exc:
        return {"loaded": False, "reason": f"{type(exc).__name__}: model file not usable (check AIDev/models/)"}


def score_html(html: str, url: str) -> dict:
    if len(html or "") < MIN_CHARS:
        return {"probability": None, "probability_calibrated": None, "threshold": None, "flagged": None,
                "signals": [], "note": f"page shorter than {MIN_CHARS} characters: not scored"}
    b = _load()
    f = cf.extract(html, url, 0, False)
    x = [[f[n] for n in b["feature_names"]]]
    p = float(b["model"].predict_proba(x)[0][1])
    cal = b.get("calibrator")
    p_cal = float(cal.predict([p])[0]) if cal is not None else None
    thr = b.get("threshold")
    flagged = bool(p_cal >= thr) if (p_cal is not None and thr is not None) else None
    return {"probability": round(p, 4),
            "probability_calibrated": None if p_cal is None else round(p_cal, 4),
            "threshold": None if thr is None else round(float(thr), 4),
            "flagged": flagged,
            "signals": signals(f),
            "note": ""}
