"""
Random Forest inference for detector.py.

    from predict import predict
    r = predict(url)      # dict, or None when the model has no opinion

None means "no opinion" (model missing, unreadable, bad URL, feature mismatch). It must
never be treated as 0 / safe. predict() never raises.
"""
from __future__ import annotations

import logging
import time

import joblib

from common import MODEL_PATH
from features import FEATURE_NAMES, FEATURE_VERSION, extract

log = logging.getLogger(__name__)
_BUNDLE = None
_LOAD_FAILED = False


def _load():
    global _BUNDLE, _LOAD_FAILED
    if _BUNDLE is not None or _LOAD_FAILED:
        return _BUNDLE
    try:
        b = joblib.load(MODEL_PATH)
        if b["feature_names"] != FEATURE_NAMES or b.get("feature_version") != FEATURE_VERSION:
            raise ValueError("features.py changed since training; retrain (python train.py)")
        b["model"].n_jobs = 1  # single URL per call: thread overhead only adds latency
        _BUNDLE = b
    except Exception as exc:
        _LOAD_FAILED = True
        log.warning("ML model unavailable: %s", exc)
    return _BUNDLE


def predict(url: str) -> dict | None:
    bundle = _load()
    if bundle is None:
        return None
    try:
        t0 = time.perf_counter()
        feats = extract(url)
        row = [[feats[n] for n in FEATURE_NAMES]]
        model = bundle["model"]
        p = float(model.predict_proba(row)[0][list(model.classes_).index(1)])

        # Per-URL explanation: global importance weighted by how extreme the value is is
        # not exact attribution; report the raw values of the most important features.
        imp = bundle["metrics"].get("feature_importance", {})
        top = {k: round(float(feats[k]), 3) for k in list(imp)[:5] if k in feats}
        return {
            "probability": round(p, 4),
            "risk_score": round(p * 100, 1),
            "model_version": bundle["version"],
            "top_features": top,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
    except Exception as exc:
        log.warning("predict failed for %r: %s", url, exc)
        return None
