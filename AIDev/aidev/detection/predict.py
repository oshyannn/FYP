"""
URL model inference for detector.py.

    from aidev.detection.predict import predict
    r = predict(url)      # dict, or None when the model has no opinion

None means "no opinion" (model missing, unreadable, bad URL, feature mismatch). It must
never be treated as 0 / safe. predict() never raises.

Two kinds of model file are understood:
  old   bundle from aidev.pipeline.train      (Random Forest, no threshold)  -> "probability" is the raw probability
  new   bundle from pipeline_own.train_final_own  (booster + character n-gram score, validated threshold)
        -> "probability" is a RISK SCORE on a rescaled 0..1 line on which the model's validated threshold sits exactly at
        WARNING_LEVEL (0.7). detector.py already treats 0.7 as the start of "Suspicious", so it needs no change.
        The raw probability, the threshold and the flag are returned as well ("raw_probability", "threshold", "flagged").
        Do not show the score as "X% chance of phishing": it is not a probability of real traffic.
"""
from __future__ import annotations

import logging
import time

import joblib

from aidev.core.common import MODEL_PATH
from aidev.core.features import FEATURE_NAMES, FEATURE_VERSION, extract

log = logging.getLogger(__name__)
WARNING_LEVEL = 0.7          # must equal detector.ML_SUSPICIOUS_PROB (check_result_shape.py tests this)
_BUNDLE = None
_LOAD_FAILED = False
_LOAD_ERROR = None
_ngram_score = None


def _load():
    global _BUNDLE, _LOAD_FAILED, _LOAD_ERROR, _ngram_score
    if _BUNDLE is not None or _LOAD_FAILED:
        return _BUNDLE
    try:
        b = joblib.load(MODEL_PATH)
        if b["feature_names"] != FEATURE_NAMES or b.get("feature_version") != FEATURE_VERSION:
            raise ValueError("features.py changed since training; retrain (python -m aidev.pipeline.train)")
        if b.get("ngram") is not None:                      # a stacked model needs the shared text helper
            from aidev.core.urltext import ngram_score
            _ngram_score = ngram_score
        if hasattr(b["model"], "n_jobs"):
            b["model"].n_jobs = 1  # single URL per call: thread overhead only adds latency
        _BUNDLE = b
    except Exception as exc:
        _LOAD_FAILED = True
        _LOAD_ERROR = _explain(exc)
        log.warning("ML model unavailable: %s", exc)
    return _BUNDLE


def _explain(exc: Exception) -> str:
    """Short, path-free reason for the screens (the full error is in the backend log)."""
    if isinstance(exc, FileNotFoundError):
        return "the model file AIDev/models/model.joblib was not found (create it with: python -m aidev.pipeline.train)"
    if isinstance(exc, ValueError) and "retrain" in str(exc):
        return "features.py changed since the model was trained (run: python -m aidev.pipeline.train)"
    return f"the model file could not be loaded ({type(exc).__name__}; see the backend log)"


def status() -> tuple[bool, str | None]:
    """(model loaded, reason it is not loaded). Lets the screens say WHY AI 1 has no result."""
    _load()
    return _BUNDLE is not None, _LOAD_ERROR


def _rescale(raw: float, thr: float | None) -> float:
    """Monotone map of the raw probability onto 0..1 with the validated threshold at WARNING_LEVEL.
    Without a threshold (old model file) the raw probability is returned unchanged."""
    if thr is None:
        return raw
    if raw < thr:
        return WARNING_LEVEL * raw / max(thr, 1e-9)
    return WARNING_LEVEL + (1 - WARNING_LEVEL) * (raw - thr) / max(1 - thr, 1e-9)


def predict(url: str) -> dict | None:
    bundle = _load()
    if bundle is None:
        return None
    try:
        t0 = time.perf_counter()
        feats = extract(url)
        row = [feats[n] for n in FEATURE_NAMES]
        ng = bundle.get("ngram")
        ng_score = None
        if ng is not None:
            ng_score = _ngram_score(ng, url)
            row.append(ng_score)                            # the booster was trained with this as its last column
        model = bundle["model"]
        raw = float(model.predict_proba([row])[0][list(model.classes_).index(1)])
        thr = bundle.get("threshold")
        p = _rescale(raw, thr)

        # Per-URL explanation: global importance weighted by how extreme the value is is
        # not exact attribution; report the raw values of the most important features.
        imp = bundle["metrics"].get("feature_importance", {})
        top = {k: round(float(feats[k]), 3) for k in list(imp)[:5] if k in feats}
        out = {
            "probability": p if thr is not None else round(p, 4),
            "risk_score": round(p * 100, 1),
            "model_version": bundle["version"],
            "top_features": top,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        }
        if thr is not None:
            out.update({"raw_probability": round(raw, 4), "threshold": float(thr), "flagged": raw >= thr,
                        "ngram_score": None if ng_score is None else round(ng_score, 4)})
        return out
    except Exception as exc:
        log.warning("predict failed for %r: %s", url, exc)
        return None
