"""
Combines every signal into one result.

Order of checks:
  1. Blacklist   (manual list, OpenPhish / URLhaus feed)  -> Malicious, 100
  2. Whitelist   (manual list + Tranco top N)             -> Safe, 5
  3. PhishTank + Random Forest                            -> highest score wins

The returned dict keeps every field the Chrome extension already reads
(status, risk_score, has_data, match_scope, ...) and adds `reasons`.
"""
from __future__ import annotations

import logging
import os
import time

import phishtank
import safebrowsing
from common import BASE, DATA, LISTS, lines, is_shared
from features import normalize, get_host, registered_domain
from predict import predict as ml_predict

log = logging.getLogger(__name__)

WHITELIST_TOP_N = 10000
THRESHOLD_SUSPICIOUS = 30
THRESHOLD_MALICIOUS = 70


def _key(url: str) -> str:
    return url.lower().split("://", 1)[-1].rstrip("/")


WHITELIST = {d.lower() for d in lines(LISTS / "whitelist.txt")}
WHITELIST |= {d.lower() for d in lines(DATA / "tranco_top.txt")[:WHITELIST_TOP_N]}
DEFAULT_TRUSTED_PREFIXES = ("drive.google.com/drive/",)      # your own Drive UI, not shared files
TRUSTED_PREFIXES = tuple(dict.fromkeys(DEFAULT_TRUSTED_PREFIXES + tuple(lines(LISTS / "trusted_prefixes.txt"))))
BLACKLIST_DOMAINS = {d.lower() for d in lines(LISTS / "blacklist.txt")}
FEED_URLS = {_key(u) for u in lines(DATA / "feeds_urls.txt")}

# --- small cache so one page does not hit PhishTank over and over -------------
_cache: dict[str, tuple[float, phishtank.PhishTankVerdict]] = {}


def _phishtank(url: str) -> phishtank.PhishTankVerdict:
    now = time.time()
    hit = _cache.get(url)
    if hit and hit[0] > now:
        return hit[1]
    verdict = phishtank.check(url, os.getenv("PHISHTANK_API_KEY") or None)
    ttl = 3600 if verdict.succeeded else 60      # retry failures soon
    if len(_cache) > 2000:
        _cache.clear()
    _cache[url] = (now + ttl, verdict)
    return verdict


# The model is lexical only (see ML_HANDOFF.md): on the test set a probability of 0.7 gives roughly
# a 2% false-positive rate, while 0.3 gives ~39%. Probabilities below ML_SUSPICIOUS_PROB therefore
# map to scores below the Suspicious threshold, and the model alone can never exceed Suspicious.
ML_SUSPICIOUS_PROB = 0.7


def _ml_to_score(p: float) -> int:
    """0..ML_SUSPICIOUS_PROB -> 0..THRESHOLD_SUSPICIOUS-1;  ML_SUSPICIOUS_PROB..1 -> THRESHOLD_SUSPICIOUS..THRESHOLD_MALICIOUS-1."""
    if p < ML_SUSPICIOUS_PROB:
        return int(p / ML_SUSPICIOUS_PROB * (THRESHOLD_SUSPICIOUS - 1))
    frac = (p - ML_SUSPICIOUS_PROB) / (1 - ML_SUSPICIOUS_PROB)
    return int(THRESHOLD_SUSPICIOUS + frac * (THRESHOLD_MALICIOUS - 1 - THRESHOLD_SUSPICIOUS))


_sb_cache: dict[str, tuple[float, safebrowsing.SafeBrowsingVerdict]] = {}


def _safebrowsing(url: str) -> safebrowsing.SafeBrowsingVerdict:
    now = time.time()
    hit = _sb_cache.get(url)
    if hit and hit[0] > now:
        return hit[1]
    verdict = safebrowsing.check(url)
    ttl = 3600 if verdict.succeeded else 60
    if len(_sb_cache) > 2000:
        _sb_cache.clear()
    _sb_cache[url] = (now + ttl, verdict)
    return verdict


def _status(score: float) -> str:
    if score >= THRESHOLD_MALICIOUS:
        return "Malicious"
    if score >= THRESHOLD_SUSPICIOUS:
        return "Suspicious"
    return "Safe"


def _result(url, status, score, source, reasons, pt=None) -> dict:
    return {
        "status": status,
        "risk_score": score if score is not None else 0,
        "has_data": score is not None,
        "url": url,
        "matched_url": pt.matched_url if pt else None,
        "match_scope": pt.match_scope if pt else None,
        "source": source,
        "phish_id": pt.phish_id if pt else None,
        "detail_url": pt.detail_url if pt else None,
        "reasons": reasons,
    }


def analyze(raw_url: str) -> dict:
    url = normalize(raw_url)
    host = get_host(url)
    if not host:
        return _result(raw_url, "Unknown", None, "none", ["Invalid URL"])
    reg = registered_domain(url)

    # 1. Blacklist (highest priority)
    if reg in BLACKLIST_DOMAINS or host in BLACKLIST_DOMAINS:
        return _result(raw_url, "Malicious", 100, "blacklist", ["Domain is in the manual blacklist"])
    if _key(url) in FEED_URLS:
        return _result(raw_url, "Malicious", 100, "blacklist", ["URL is in the OpenPhish / URLhaus feed"])

    # 2. Whitelist (shared hosting platforms are excluded on purpose)
    if reg in WHITELIST and not is_shared(host):
        return _result(raw_url, "Safe", 5, "whitelist", [f"{reg} is a known trusted domain"])

    # 2b. Trusted application paths on shared hosts (e.g. your own Google Drive UI)
    if TRUSTED_PREFIXES and _key(url).startswith(TRUSTED_PREFIXES):
        return _result(raw_url, "Safe", 5, "whitelist", ["Trusted application path"])

    # 3. PhishTank + Random Forest
    scores: list[float] = []
    reasons: list[str] = []
    pt = None

    shared = is_shared(host)
    pt = _phishtank(url)
    if pt.succeeded and shared and pt.match_scope == "domain":
        # on a public platform the "domain" is shared by thousands of unrelated sites
        reasons.append("PhishTank domain-level match ignored (public hosting platform)")
        pt = None
    elif not pt.succeeded:
        log.warning("PhishTank lookup failed: %s", pt.error)
        reasons.append("PhishTank unavailable (lookup failed)")
        pt = None
    elif pt.risk_contribution is not None:
        scores.append(pt.risk_contribution)
        reasons.append(f"PhishTank {pt.match_scope} match (phish_id {pt.phish_id})")
    elif pt.found:
        reasons.append("PhishTank record exists but was voted not-phishing")
        pt = None
    else:
        pt = None

    # Google Safe Browsing (inactive unless GOOGLE_SAFE_BROWSING_API_KEY is set)
    sb = _safebrowsing(url)
    sb_score = sb.risk_contribution
    if not sb.configured:
        pass
    elif not sb.succeeded:
        log.warning("Safe Browsing lookup failed: %s", sb.error)
        reasons.append("Google Safe Browsing unavailable (lookup failed)")
    elif sb_score is not None:
        scores.append(sb_score)
        reasons.append(f"Google Safe Browsing lists this URL ({sb.threat_type})")

    # On shared platforms the path is a random document ID, which says nothing about the page, so only
    # the host is shown to the model there (it still sees e.g. "paypal-login.github.io").
    ml = ml_predict(f"https://{host}/" if shared else url)   # None = no opinion, never 0
    ml_score = None
    if ml is not None:
        ml_score = _ml_to_score(ml["probability"])
        scores.append(ml_score)
        reasons.append(f"ML model phishing probability {ml['probability']:.0%}")

    pt_score = pt.risk_contribution if pt is not None else None
    non_ml = [x for x in (pt_score, sb_score) if x is not None]

    if shared:
        if max(scores, default=0) < 60:               # no confirmed evidence: explain the mild warning
            reasons.append("Hosted on a public platform where anyone can publish. "
                           "This alone does not mean the page is malicious.")
        scores.append(THRESHOLD_SUSPICIOUS)          # mild warning floor, far below Malicious
        non_ml.append(THRESHOLD_SUSPICIOUS)

    score = max(scores, default=None)

    # Two independent sources agreeing is stronger than either one: a PhishTank record that is not yet
    # voted on (60) plus a model that also finds the URL suspicious is treated as Malicious.
    if pt_score is not None and pt_score >= 60 and ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS:
        score = max(score, THRESHOLD_MALICIOUS)
        reasons.append("PhishTank record and ML model agree")

    if score is None:
        return _result(raw_url, "Unknown", None, "none", reasons or ["No data from any source"])

    # "Safe" must rest on evidence of safety. A model that merely sees nothing suspicious cannot
    # vouch for a site (e.g. a phishing page on a normal-looking domain), so that case is Unknown.
    if _status(score) == "Safe" and not non_ml:
        reasons.append("No strong phishing signal from the model. This is not a guarantee that the site is safe.")
        return _result(raw_url, "Unknown", None, "model", reasons)

    source = "+".join(n for n, on in (("phishtank", pt is not None), ("safebrowsing", sb_score is not None),
                                      ("model", ml is not None)) if on) or "shared-host"
    return _result(raw_url, _status(score), score, source, reasons, pt)
