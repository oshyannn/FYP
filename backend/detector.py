"""
Combines every signal into one result.

Order of checks:
  1. Blacklist   (manual list, OpenPhish / URLhaus feed)  -> Malicious, 100
  2. Whitelist   (manual list + Tranco top N)             -> Safe, 5
  3. PhishTank + look-alike + Safe Browsing + URL model (ML1) + domain age + page content model (ML2) + downloads
     -> highest score wins, independent signals that agree raise it to Malicious

Results of the slow path (step 3) are cached per URL (see analyze()). List hits are instant and not cached.

The returned dict keeps every field the Chrome extension already reads
(status, risk_score, has_data, match_scope, ...) and adds `reasons`.
"""
from __future__ import annotations

import logging
import os
import time

import phishtank
import rdap
import predict_content
import lookalike
import safebrowsing
from common import BASE, DATA, LISTS, lines, is_shared
from features import normalize, get_host, registered_domain
from predict import predict as ml_predict

log = logging.getLogger(__name__)

WHITELIST_TOP_N = 10000
THRESHOLD_SUSPICIOUS = 30
THRESHOLD_MALICIOUS = 70
LOOKALIKE_SCORE = 50          # "looks like a domain we know": Suspicious-level evidence, never Malicious alone


def _key(url: str) -> str:
    return url.lower().split("://", 1)[-1].rstrip("/")


# Tranco ranks sites by traffic, not by trustworthiness: ad networks, redirectors and some shady sites
# sit in the top 10,000. lists/not_trusted.txt removes such domains from the Tranco part of the whitelist
# (it never overrides lists/whitelist.txt, which is your own explicit choice).
NOT_TRUSTED = {d.lower() for d in lines(LISTS / "not_trusted.txt")}
WHITELIST = {d.lower() for d in lines(LISTS / "whitelist.txt")}
WHITELIST |= {d.lower() for d in lines(DATA / "tranco_top.txt")[:WHITELIST_TOP_N]} - NOT_TRUSTED
DEFAULT_TRUSTED_PREFIXES = ("drive.google.com/drive/",)      # your own Drive UI, not shared files
TRUSTED_PREFIXES = tuple(dict.fromkeys(DEFAULT_TRUSTED_PREFIXES + tuple(lines(LISTS / "trusted_prefixes.txt"))))
TRUSTED_SUFFIXES = tuple("." + x for x in lines(LISTS / "trusted_suffixes.txt"))
# Adult content is not malware, so it has its own status ("Restricted") and its own switch.
# BLOCK_ADULT=0 (environment or .env) turns it off. Your own lists/whitelist.txt always wins.
BLOCK_ADULT = os.getenv("BLOCK_ADULT", "1").strip().lower() not in {"0", "false", "no", "off"}
ADULT = {d.lower() for d in lines(DATA / "adult_domains.txt") + lines(LISTS / "adult_manual.txt")}
MANUAL_WHITELIST = {d.lower() for d in lines(LISTS / "whitelist.txt")}


def _is_adult(host: str) -> bool:
    parts = host.split(".")
    return any(".".join(parts[i:]) in ADULT for i in range(len(parts) - 1))


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

# The content model reads the page itself (forms, title vs domain, hidden iframes...). Measured on pages you crawled
# yourself (model_content_metrics.json, eval_mode own-pages-test, AUC 0.76):
#     threshold  0.7 -> 7.8% of benign pages flagged, 41% of phishing caught   (login pages: 21% flagged)
#     threshold  0.8 -> 1.8% of benign pages flagged, 20% of phishing caught
# At 0.7 it would warn on about 1 in 13 normal sites, so Suspicious starts at 0.8 (about the same false-positive rate
# as ML1 at 0.7). Alone it reaches at most CONTENT_MAX_ALONE; it becomes Malicious only when another independent signal
# agrees. Re-check these numbers whenever train_content.py is run again.
CONTENT_SUSPICIOUS_PROB = 0.8
CONTENT_MAX_ALONE = 65

# A page that starts a download of a program file (exe/msi/apk...) by itself. Suspicious alone (legitimate software
# sites do it too); Malicious when another independent signal agrees. An address that IS the file (direct download)
# is not scored on its own: the extension's download guard asks the person, and a score here would turn every
# "ask" into a hard block. It only counts together with a strong warning sign (look-alike, brand-new domain, PhishTank).
DOWNLOAD_AUTO_SCORE = 55

# How long a finished verdict is reused (seconds). Verdicts built on a failed lookup are retried sooner.
RESULT_TTL = {"Malicious": 6 * 3600, "Restricted": 6 * 3600, "Suspicious": 3600, "Safe": 3600, "Unknown": 3600}
RESULT_TTL_PARTIAL = 300
_INSTANT_SOURCES = {"blacklist", "whitelist", "trusted-suffix", "adult-list"}     # lookups in memory: not worth caching
_result_cache: dict[str, tuple[float, dict]] = {}


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


def _refine_lookalike(la: dict, reg: str) -> tuple[int, list[str], bool]:
    """Use registration data (RDAP) to sharpen a look-alike hit. Returns (score, notes, same_owner).
    Lookup failure or redacted data changes nothing: the base score stays and no conclusion is drawn."""
    mine = rdap.lookup(reg)
    if not mine.succeeded:
        return LOOKALIKE_SCORE, ["Domain registration data unavailable, so ownership could not be checked"], False
    target = rdap.lookup(la["target"])
    if mine.registrant and target.succeeded and target.registrant and mine.registrant == target.registrant:
        return 0, [f"{reg} and {la['target']} are registered to the same organisation, so this is likely the owner's own domain"], True
    notes, score, age = [], LOOKALIKE_SCORE, mine.age_days
    if age is not None:
        if age < 30:
            score = 65
            notes.append(f"Domain was registered only {age} days ago")
        elif age < 180:
            score = 55
            notes.append(f"Domain was registered {age} days ago (recent)")
        elif age >= 5 * 365:
            score = 35
            notes.append(f"Domain is {age // 365} years old, which makes a scam somewhat less likely")
    if not (mine.registrant and target.registrant):
        notes.append("Registrant is hidden, so whether both domains share an owner cannot be told")
    return score, notes, False


def _content_to_score(p: float) -> int:
    """0..CONTENT_SUSPICIOUS_PROB -> 0..29;  CONTENT_SUSPICIOUS_PROB..1 -> 30..CONTENT_MAX_ALONE."""
    if p < CONTENT_SUSPICIOUS_PROB:
        return int(p / CONTENT_SUSPICIOUS_PROB * (THRESHOLD_SUSPICIOUS - 1))
    frac = (p - CONTENT_SUSPICIOUS_PROB) / (1 - CONTENT_SUSPICIOUS_PROB)
    return int(THRESHOLD_SUSPICIOUS + frac * (CONTENT_MAX_ALONE - THRESHOLD_SUSPICIOUS))


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
    """Verdict for one URL. Slow-path verdicts are cached, so the same page is not downloaded and looked up again."""
    key = normalize(raw_url)
    now = time.time()
    hit = _result_cache.get(key)
    if hit and hit[0] > now:
        return {**hit[1], "url": raw_url, "cached": True}
    result = _analyze(raw_url)
    if result.get("source") not in _INSTANT_SOURCES and "Invalid URL" not in result.get("reasons", []):
        partial = any(("unavailable" in r) or ("could not be read" in r) for r in result.get("reasons", []))
        ttl = RESULT_TTL_PARTIAL if partial else RESULT_TTL.get(result["status"], 3600)
        if len(_result_cache) > 5000:
            _result_cache.clear()
        _result_cache[key] = (now + ttl, result)
    return result


def _analyze(raw_url: str) -> dict:
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

    # 1b. Adult content (before the Tranco whitelist: popular adult sites sit in the top 10,000 too)
    if BLOCK_ADULT and ADULT and reg not in MANUAL_WHITELIST and host not in MANUAL_WHITELIST and _is_adult(host):
        r = _result(raw_url, "Restricted", 100, "adult-list", ["Adult content site (blocked by your adult-site list)"])
        r["category"] = "adult"
        return r

    # 2. Whitelist (shared hosting platforms are excluded on purpose)
    if reg in WHITELIST and not is_shared(host):
        return _result(raw_url, "Safe", 5, "whitelist", [f"{reg} is a known trusted domain"])

    # 2a. Endings only verified institutions can register (edu.my, gov.my ...)
    if TRUSTED_SUFFIXES and not is_shared(host) and ("." + reg).endswith(TRUSTED_SUFFIXES):
        return _result(raw_url, "Safe", 10, "trusted-suffix", [f"{reg} uses a restricted institutional domain ending"])

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

    # Look-alike of a protected domain (typo / homoglyph / extra words); not meaningful on shared platforms
    la = None if shared else lookalike.check(host)
    la_score = LOOKALIKE_SCORE if la else None
    if la:
        la_score, la_notes, same_owner = _refine_lookalike(la, reg)
        if same_owner:
            la, la_score = None, None
            reasons.extend(la_notes)
        else:
            scores.append(la_score)
            reasons.append(f"Look-alike domain: {la['reason']}. This does not prove it is malicious.")
            reasons.extend(la_notes)

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
    non_ml = [x for x in (pt_score, sb_score, la_score) if x is not None]

    if shared:
        if max(scores, default=0) < 60:               # no confirmed evidence: explain the mild warning
            reasons.append("Hosted on a public platform where anyone can publish. "
                           "This alone does not mean the page is malicious.")
        scores.append(THRESHOLD_SUSPICIOUS)          # mild warning floor, far below Malicious
        non_ml.append(THRESHOLD_SUSPICIOUS)

    score = max(scores, default=None)

    # Domain age for every site that no list knows about. Phishing domains are mostly days old, whatever
    # their name looks like, so this works where the URL text (model) and look-alike rules see nothing.
    # Old domain + only a weak model suspicion -> relax. Lookup failure (or a ccTLD without RDAP) changes nothing.
    age_new = False
    if not non_ml and not shared:
        info = rdap.lookup(reg)
        age = info.age_days if info.succeeded else None
        if age is not None and age < 30:
            age_new = True
            score = max(score or 0, 55 if (ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS) else 45)
            non_ml.append(45)
            reasons.append(f"Domain was registered only {age} days ago and is on no list (new domains are common in phishing)")
        elif age is not None and age >= 730 and score is not None and score >= THRESHOLD_SUSPICIOUS:
            score = THRESHOLD_SUSPICIOUS - 1
            reasons.append(f"Domain is {age // 365} years old, which outweighs the model's weak suspicion")

    # Page content: download the page and read it. Skipped when a list already says Malicious (saves time) and on shared
    # platforms (training data has none). The same download also shows whether the address is a program-file download
    # or the page starts one by itself, which works even when the content model is not trained.
    content = None
    content_score = None
    download_score = None
    download_direct = None
    if not shared and max([x for x in (pt_score, sb_score) if x is not None], default=0) < 70 and predict_content.enabled():
        content = predict_content.predict(url)
        if content is not None:
            dl = content.get("download")
            if dl and content.get("download_kind") == "direct":
                download_direct = dl
                reasons.append(f"This address starts a download of a program file ({dl}) instead of opening a page")
            elif dl:
                download_score = DOWNLOAD_AUTO_SCORE
                score = max(score or 0, download_score)
                non_ml.append(download_score)
                reasons.append(f"The page tries to start a download of a program file ({dl}) by itself")
            if content.get("probability") is not None:
                content_score = _content_to_score(content["probability"])
                score = max(score or 0, content_score)
                reasons.append(f"Page content analysis: phishing probability {content['probability']:.0%}")
                if content_score >= THRESHOLD_SUSPICIOUS:
                    reasons.extend(f"Page {s_}" for s_ in content["signals"][:3])
                    non_ml.append(content_score)
        else:
            reasons.append("Page content could not be read (unreachable, not plain HTML, or built by JavaScript)")

    # Two independent sources agreeing is stronger than either one: a PhishTank record that is not yet
    # voted on (60) plus a model that also finds the URL suspicious is treated as Malicious.
    if pt_score is not None and pt_score >= 60 and ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS:
        score = max(score, THRESHOLD_MALICIOUS)
        reasons.append("PhishTank record and ML model agree")

    # A look-alike name that the model also finds suspicious: two independent weak signals agree.
    if content_score is not None and content_score >= THRESHOLD_SUSPICIOUS and (
            age_new or la_score is not None or (ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS)
            or (pt_score is not None and pt_score >= 60)):
        score = max(score, THRESHOLD_MALICIOUS)
        reasons.append("Page content and another independent signal agree")

    if la_score is not None and ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS:
        score = max(score, THRESHOLD_MALICIOUS)
        reasons.append("Look-alike domain and ML model agree")

    # Downloads: a program file pushed by the page, or served straight from the address, together with another warning sign.
    strong_other = age_new or la_score is not None or (pt_score is not None and pt_score >= 60)
    if download_direct and strong_other:
        score = max(score or 0, THRESHOLD_MALICIOUS)
        reasons.append("Program-file download from a site that also shows another warning sign")
    if download_score is not None and (strong_other
                                       or (content_score is not None and content_score >= THRESHOLD_SUSPICIOUS)
                                       or (ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS)):
        score = max(score, THRESHOLD_MALICIOUS)
        reasons.append("Automatic download and another independent signal agree")

    if score is None:
        return _result(raw_url, "Unknown", None, "none", reasons or ["No data from any source"])

    # "Safe" must rest on evidence of safety. A model that merely sees nothing suspicious cannot
    # vouch for a site (e.g. a phishing page on a normal-looking domain), so that case is Unknown.
    if _status(score) == "Safe" and not non_ml:
        reasons.append("No strong phishing signal from the model. This is not a guarantee that the site is safe.")
        return _result(raw_url, "Unknown", None, "model", reasons)

    source = "+".join(n for n, on in (("phishtank", pt is not None), ("safebrowsing", sb_score is not None),
                                      ("lookalike", la_score is not None), ("domain-age", age_new), ("content", content_score is not None),
                                      ("download", download_score is not None or download_direct is not None),
                                      ("model", ml is not None)) if on) or "shared-host"
    return _result(raw_url, _status(score), score, source, reasons, pt)
