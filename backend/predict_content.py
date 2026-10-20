"""
Content model inference for detector.py.

    from predict_content import predict
    r = predict(url)     # dict or None

Downloads the page (pagefetch.py), extracts features (content_features.py) and asks the content Random Forest.
Returned dict:
    probability    float 0..1, or None when only a download was found / the model is missing
    signals        plain-language reasons from the page
    final_url      address after redirects
    download       file name of a program file, or None
    download_kind  "direct" = the address itself IS the file (answered with a download)
                   "auto"   = the HTML page tries to start the download by itself (meta refresh, script, hidden iframe)
None = no opinion (page unreachable / not HTML / JavaScript-only and no download): never 0 / safe.
predict() never raises. Results are cached for 10 minutes. CONTENT_CHECK=0 in the environment switches it off.
"""
from __future__ import annotations

import logging
import os
import re
import time
from urllib.parse import urljoin, urlsplit

import joblib

import content_features as cf
import pagefetch
from common import CONTENT_MODEL_PATH

log = logging.getLogger(__name__)
_BUNDLE = None
_LOAD_FAILED = False
_cache: dict[str, tuple[float, dict | None]] = {}

# Targets the page sends the browser to by itself. A link the person has to click is NOT counted here.
_AUTO_TARGETS = (
    re.compile(r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)""", re.I),
    re.compile(r"""\blocation(?:\.href)?\s*=\s*["']([^"']+)["']""", re.I),
    re.compile(r"""\blocation\.(?:replace|assign)\s*\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""\bwindow\.open\s*\(\s*["']([^"']+)["']""", re.I),
    re.compile(r"""<iframe\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I),
)
_A_DOWNLOAD = re.compile(r"""<a\b[^>]*\bdownload\b[^>]*\bhref\s*=\s*["']([^"']+)["']|<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*\bdownload\b""", re.I)
_SCRIPT_CLICK = re.compile(r"\.click\s*\(")


def enabled() -> bool:
    return os.getenv("CONTENT_CHECK", "1").strip().lower() not in {"0", "false", "no", "off"}


def _load():
    global _BUNDLE, _LOAD_FAILED
    if _BUNDLE is not None or _LOAD_FAILED:
        return _BUNDLE
    try:
        b = joblib.load(CONTENT_MODEL_PATH)
        if b.get("feature_version") != cf.CONTENT_FEATURE_VERSION or any(n not in cf.FEATURE_NAMES for n in b["feature_names"]):
            raise ValueError("content_features.py changed since training; retrain (python train_content.py)")
        b["model"].n_jobs = 1
        _BUNDLE = b
    except Exception as exc:
        _LOAD_FAILED = True
        log.info("content model unavailable: %s", exc)
    return _BUNDLE


def available() -> bool:
    return enabled() and _load() is not None


def signals(f: dict) -> list[str]:
    """Plain-language reasons taken from the raw features (what a human reviewer would notice)."""
    out = []
    if f["has_password_field"] and f["form_external_action"]:
        out.append("asks for a password and sends it to a different website")
    elif f["has_password_field"] and (f["form_null_action"] or f["form_script_or_mail_action"]):
        out.append("password form that submits to a script or nowhere")
    if f["brand_in_title_not_domain"]:
        out.append("page title names a well-known brand that this domain does not belong to")
    if f["hidden_iframe"]:
        out.append("contains a hidden iframe")
    if f["obfuscation_density"] > 3:
        out.append("heavily obfuscated JavaScript")
    if f["rightclick_blocked"]:
        out.append("blocks right-click")
    if f["ext_resource_ratio"] > 0.6 and f["n_images"] + f["n_scripts"] > 3:
        out.append("loads most images/scripts from other websites")
    if f["meta_refresh"]:
        out.append("redirects automatically (meta refresh)")
    if f["tls_invalid"]:
        out.append("invalid HTTPS certificate")
    if f["redirect_cross_domain"]:
       out.append("redirects you to a different website")
    return out


def auto_download(html: str, final_url: str) -> str | None:
    """File name if the page itself sends the browser to a program file (meta refresh, script redirect, iframe,
    or a script that clicks a download link). Static text search only; nothing is run."""
    html = (html or "")[:400_000]
    targets: list[str] = []
    for rx in _AUTO_TARGETS:
        targets += [m.group(1) for m in rx.finditer(html)]
    if _SCRIPT_CLICK.search(html):
        for m in _A_DOWNLOAD.finditer(html):
            targets.append(m.group(1) or m.group(2))
    for t in targets:
        try:
            path = urlsplit(urljoin(final_url, t.strip())).path
        except ValueError:
            continue
        if pagefetch.RISKY_FILE.search(path):
            return path.rsplit("/", 1)[-1]
    return None


def predict(url: str) -> dict | None:
    if not enabled():
        return None
    now = time.time()
    hit = _cache.get(url)
    if hit and hit[0] > now:
        return hit[1]
    result = _predict(url)
    if len(_cache) > 1000:
        _cache.clear()
    _cache[url] = (now + 600, result)
    return result


def _predict(url: str) -> dict | None:
    try:
        t0 = time.perf_counter()
        page = pagefetch.fetch(url)
        ms = lambda: round((time.perf_counter() - t0) * 1000, 1)
        if page.download:                                   # the address itself is a program file; nothing to read
            return {"probability": None, "signals": [], "final_url": page.url, "download": page.download,
                    "download_kind": "direct", "model_version": None, "latency_ms": ms()}
        if not page.ok or not page.html:
            log.info("content check skipped for %s: %s", url, page.error)
            return None
        auto = auto_download(page.html, page.url)
        p, sigs, version = None, [], None
        b = _load()
        if b is not None and len(page.html) >= 200:
            f = cf.extract(page.html, page.url, page.redirects, page.tls_invalid)
            p = float(b["model"].predict_proba([[f[n] for n in b["feature_names"]]])[0][1])
            sigs, version = signals(f), b.get("version")
        if p is None and not auto:
            return None
        return {"probability": p, "signals": sigs, "final_url": page.url, "download": auto,
                "download_kind": "auto" if auto else None, "model_version": version, "latency_ms": ms()}
    except Exception as exc:
        log.warning("content check failed: %s", exc)
        return None
