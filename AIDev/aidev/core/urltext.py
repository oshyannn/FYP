"""
Text helpers for the URL model's character n-gram score.  Own code.

Training (pipeline_own/train_final_own.py) and prediction (detection/predict.py) both import these two functions, so the
text that is scored is built the same way in both places. Put this file in  AIDev/aidev/core/urltext.py
"""
from __future__ import annotations

from urllib.parse import urlsplit

from aidev.core.features import normalise


def ngram_text(url: str, host_only: bool = True) -> str:
    """Lower-case host without a leading 'www.' (plus the path when host_only is False)."""
    p = urlsplit(normalise(url))
    host = p.hostname or ""
    host = host[4:] if host.startswith("www.") else host
    return (host if host_only else host + (p.path or "")).lower()


def ngram_score(ng: dict, url: str) -> float:
    """Phishing score (0..1) of the character n-gram model stored in a model bundle under the key 'ngram'."""
    vec = ng["vectorizer"].transform([ngram_text(url, ng.get("host_only", True))])
    lin = ng["linear"]
    return float(lin.predict_proba(vec)[0][list(lin.classes_).index(1)])
