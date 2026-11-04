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

It also carries the structured parts the screens show (see the block "Structured output for the screens" below):
`checks` (every source: used / found nothing / not configured / skipped), `ai1`, `ai2` (with one percentage per kind of
page threat), `ai_combined` and `final` (lists / APIs + AI -> the overall danger).
"""
from __future__ import annotations

import logging
import os
import time

from aidev.detection import phishtank
from concurrent.futures import ThreadPoolExecutor

from aidev.detection import cert_history
from aidev.detection import domain_age
from aidev.detection import official_site
from aidev.detection import popularity
from aidev.detection import predict as ai1_model
from aidev.detection import rdap
from aidev.detection import predict_content
from aidev.detection import lookalike
from aidev.detection import page_threats
from aidev.detection import safebrowsing
from aidev.core.common import DATA, LISTS, lines, is_shared
from aidev.core.features import normalize, get_host, registered_domain
from aidev.detection.predict import predict as ml_predict

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
ESTABLISHED_SAFE = os.getenv("ESTABLISHED_SAFE", "1") != "0"   # old + popular + nothing reported -> Safe

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


# ---------------------------------------------------------------------------------------------------------------------
# Structured output for the screens (desktop app and extension).
#
# The decision logic below is unchanged. What is new is that the result now ALSO says, for every source that exists, whether
# it was used and what it found, so a demo can show exactly which sources took part:
#   checks        one entry per source (lists, PhishTank, Safe Browsing, look-alike, domain age, AI 1, AI 2): state + detail
#   ai1           URL model: phishing probability (%) and a description
#   ai2           page-content model: phishing probability (%), description, and one percentage per kind of page threat
#                 (fake login page, fake bank / payment page, hidden download ...), see page_threats.py
#   ai_combined   AI 1 and AI 2 together: one risk score and a description
#   final         lists / APIs score + AI score -> the final risk, with a plain-language summary
# Every old field (status, risk_score, has_data, source, reasons ...) keeps its meaning.
# ---------------------------------------------------------------------------------------------------------------------
PROVIDERS = (
    ("blacklist", "Manual blacklist", "list"),
    ("feed", "OpenPhish / URLhaus feed", "list"),
    ("adult", "Adult-site list", "list"),
    ("whitelist", "Trusted list (top sites, your own list, institutional endings)", "list"),
    ("phishtank", "PhishTank", "api"),
    ("safebrowsing", "Google Safe Browsing", "api"),
    ("lookalike", "Look-alike domain check", "rule"),
    ("domain_age", "Domain age (RDAP / WHOIS / web archive)", "rule"),
    ("popularity", "Popularity rank (Tranco top 300,000)", "rule"),
    ("certs", "Certificate history (CT logs) and certificate owner", "rule"),
    ("wikidata", "Official-website cross-check (Wikidata)", "rule"),
    ("ai1", "AI 1: URL model", "ai"),
    ("ai2", "AI 2: page content model", "ai"),
)
AI1_NAME = "AI 1: URL model"
AI2_NAME = "AI 2: page content model"
AI_COMBINED_NAME = "AI combined (AI 1 + AI 2)"
AI2_BASE = ("Downloads the page and reads it: forms, password and card fields, page title versus domain, hidden frames, scripts "
            "and downloads that start by themselves.")
FINAL_METHOD = ("The final score is the highest score of the lists / APIs and the AI models. When two independent signals agree "
                "(for example a PhishTank record and the URL model, or both AI models) it is raised to the Malicious level (70). "
                "A site is called Safe only with positive evidence: a trusted list, or an established site (old, widely visited, nothing reported). Otherwise 'nothing found' stays Unknown, with an explanation of what was and was not checked.")


class _Checks:
    """What each source said about this URL. state: match | clear | unavailable | not_configured | skipped | no_opinion.
    effect (only for a match): "risk" = evidence against the site, "trust" = a trusted list vouches for it."""

    def __init__(self) -> None:
        self._d: dict[str, dict] = {}

    def add(self, pid: str, state: str, detail: str, score=None, effect: str = "none") -> None:
        self._d[pid] = {"state": state, "detail": detail, "score": score, "effect": effect}

    def skip_rest(self, why: str) -> None:
        for pid, _name, _group in PROVIDERS:
            self._d.setdefault(pid, {"state": "skipped", "detail": why, "score": None, "effect": "none"})

    def as_list(self) -> list[dict]:
        out = []
        for pid, name, group in PROVIDERS:
            e = self._d.get(pid) or {"state": "skipped", "detail": "Not run", "score": None, "effect": "none"}
            out.append({"id": pid, "name": name, "group": group, **e})
        return out


def _pct(p: float) -> int:
    return int(round(p * 100))


def _ai_level(score) -> str:
    if score is None:
        return "none"
    return "high" if score >= THRESHOLD_MALICIOUS else "elevated" if score >= THRESHOLD_SUSPICIOUS else "low"


def _age_text(days: int) -> str:
    return f"{days} days" if days < 60 else f"{days // 30} months" if days < 730 else f"{days // 365} years"


def _ai_off(why: str) -> dict:
    """AI blocks for a result that did not need the models (a local list already decided it)."""
    base = {"state": "skipped", "available": False, "probability": None, "percent": None, "score": None, "level": "none", "description": why}
    return {"ai1": {"name": AI1_NAME, **base},
            "ai2": {"name": AI2_NAME, **base, "categories": [], "signals": [], "download": None, "page_read": False},
            "ai_combined": {"name": AI_COMBINED_NAME, "state": "skipped", "score": None, "percent": None, "level": "none", "description": why}}


def _ai1_why() -> str:
    try:
        loaded, reason = ai1_model.status()
    except Exception:
        return "the model could not be checked"
    return "the address could not be scored" if loaded else (reason or "the model is not loaded")


def _ai1_block(ml: dict | None, ml_score: int | None, shared: bool) -> dict:
    base = "Reads only the text of the address (length, symbols, keywords, brand names, domain structure), not the page itself."
    if ml is None:
        why = _ai1_why()
        return {"name": AI1_NAME, "state": "no_opinion", "available": False, "probability": None, "percent": None, "score": None,
                "level": "none", "description": base + f" It gave no opinion: {why}. That is not a sign that the site is safe, and "
                                                   "it does not count for or against the site."}
    p = ml["probability"]
    if p >= ML_SUSPICIOUS_PROB:
        verdict = "The address looks like known phishing addresses."
    elif p >= 0.4:
        verdict = f"Some parts of the address resemble phishing, but it is below the warning level ({ML_SUSPICIOUS_PROB:.0%})."
    else:
        verdict = "The address shows no strong phishing pattern. That does not prove the site is safe."
    note = " On a public hosting platform only the host name is scored, because the path is a random document ID." if shared else ""
    return {"name": AI1_NAME, "state": "ok", "available": True, "probability": _pct(p), "percent": _pct(p), "score": ml_score,
            "level": _ai_level(ml_score),
            "description": f"{base} Phishing probability {_pct(p)}%. {verdict} On its own it can raise Suspicious but never Malicious.{note}"}


def _ai2_block(content: dict | None, ai2_score: int | None, skipped_why: str | None) -> dict:
    base = AI2_BASE
    empty = {"name": AI2_NAME, "available": False, "probability": None, "percent": None, "score": None, "level": "none",
             "categories": [], "signals": [], "download": None, "page_read": False}
    if skipped_why:
        return {**empty, "state": "skipped", "description": skipped_why}
    if content is None:
        return {**empty, "state": "no_opinion",
                "description": base + " The page could not be read (unreachable, not plain HTML, or built by JavaScript), so there is "
                                      "no page result. That is not a sign that the site is safe."}
    p = content.get("probability")
    cats = page_threats.assess(content.get("features"), content.get("download"), content.get("download_kind"), content.get("page_signals"))
    dl = {"kind": content.get("download_kind"), "file": content.get("download")} if content.get("download") else None
    if p is None:
        try:
            loaded, reason = predict_content.status()
        except Exception:
            loaded, reason = True, None
        head = (f" The page model gave no probability ({reason if not loaded else 'the page has almost no text to judge'}), "
                "so only the rule-based checks below were used.")
    elif p >= CONTENT_SUSPICIOUS_PROB:
        head = f" Phishing probability {_pct(p)}%. The page looks like known phishing pages."
    elif p >= 0.5:
        head = f" Phishing probability {_pct(p)}%. Some page features resemble phishing, but it is below the warning level ({CONTENT_SUSPICIOUS_PROB:.0%})."
    else:
        head = f" Phishing probability {_pct(p)}%. The page shows no strong phishing pattern. That does not prove the site is safe."
    hot = [c for c in cats if c["triggered"]]
    tail = (" Main concerns: " + ", ".join(f"{c['label']} {c['percent']}%" for c in hot) + ".") if hot else \
        " None of the threat kinds below reached the warning level."
    return {"name": AI2_NAME, "state": "ok", "available": p is not None or dl is not None or bool(cats),
            "probability": None if p is None else _pct(p), "percent": None if p is None else _pct(p), "score": ai2_score,
            "level": _ai_level(ai2_score), "description": base + head + tail, "categories": cats,
            "signals": list(content.get("signals") or []), "download": dl, "page_read": content.get("features") is not None}


def _ai_combined(s1: int | None, s2: int | None) -> dict:
    """AI 1 + AI 2 as the detector treats them: the higher score counts, and when BOTH raise a warning they are
    independent evidence and the combined result is Malicious level."""
    parts = [s for s in (s1, s2) if s is not None]
    base = {"name": AI_COMBINED_NAME}
    if not parts:
        return {**base, "state": "no_opinion", "score": None, "percent": None, "level": "none",
                "description": "Neither AI model could score this site, so there is no AI result. That is not a sign that the site is safe."}
    score = max(parts)
    names = {1: "AI 1 (URL model)", 2: "AI 2 (page content)"}
    if s1 is not None and s2 is not None:
        if s1 >= THRESHOLD_SUSPICIOUS and s2 >= THRESHOLD_SUSPICIOUS:
            score = max(score, THRESHOLD_MALICIOUS)
            text = (f"AI 1 and AI 2 both raise a warning (risk {s1} and {s2}). Two independent models agreeing is strong evidence, "
                    "so the combined AI risk is raised to the Malicious level.")
        elif score >= THRESHOLD_SUSPICIOUS:
            who = names[1] if s1 >= THRESHOLD_SUSPICIOUS else names[2]
            text = f"Only {who} raises a warning (risk {score}); the other model sees no strong sign. One model alone is not trusted to call a site malicious, so the combined AI risk stays at the Suspicious level."
        else:
            text = f"Neither AI model sees a strong warning sign (risk {s1} and {s2}). That is not a guarantee that the site is safe."
    else:
        only = names[1] if s1 is not None else names[2]
        other = names[2] if s1 is not None else names[1]
        text = (f"Only {only} produced a result ({other} had no opinion), so the combined AI risk is {score}. "
                + ("A single model can raise Suspicious but never Malicious on its own." if score >= THRESHOLD_SUSPICIOUS
                   else "No strong warning sign, but that is not a guarantee that the site is safe."))
    return {**base, "state": "ok", "score": score, "percent": score, "level": _ai_level(score), "description": text}


def _list_api_text(checks: list[dict]) -> str:
    risk = [c for c in checks if c["group"] != "ai" and c["state"] == "match" and c["effect"] == "risk"]
    if risk:
        return "Reported by " + "; ".join(f"{c['name']} ({c['detail']})" for c in risk) + "."
    trust = [c for c in checks if c["group"] != "ai" and c["state"] == "match" and c["effect"] == "trust"]
    if trust:
        return trust[0]["detail"] + "."
    checked = [c["name"] for c in checks if c["group"] in ("api", "rule") and c["state"] == "clear"]
    if any(c["group"] == "list" and c["state"] == "clear" for c in checks):
        checked.insert(0, "local lists")
    text = "No list, API or domain rule reported this URL" + (f" (checked: {', '.join(checked)})" if checked else "") + "."
    unused = [f"{c['name']} ({'no API key' if c['state'] == 'not_configured' else 'lookup failed' if c['state'] == 'unavailable' else 'no data'})"
              for c in checks if c["group"] in ("api", "rule") and c["state"] in ("not_configured", "unavailable", "no_opinion")]
    return text + (" Not used: " + "; ".join(unused) + "." if unused else "")


def _assessment(status: str, score, checks: list[dict], ai_comb: dict, ctx: dict) -> dict:
    """The honest answer for the person: what speaks for the site, what speaks against it, what could not be checked, and how
    sure we are. Replaces a bare "not enough data"."""
    supporting, concerns, missing = [], [], []
    for c in checks:
        if c["state"] == "match" and c["effect"] == "risk":
            concerns.append(f"{c['name']}: {c['detail']}")
        elif c["state"] == "match" and c["effect"] == "trust":
            supporting.append(f"{c['name']}: {c['detail']}")
        elif c["state"] in ("clear", "info") and c["group"] in ("api", "rule", "ai"):
            supporting.append(f"{c['name']}: {c['detail']}")
        elif c["state"] in ("unavailable", "not_configured", "no_opinion"):
            missing.append(f"{c['name']}: {c['detail']}")
    if any(c["group"] == "list" and c["state"] == "clear" for c in checks) and not any(c["group"] == "list" and c["state"] == "match" for c in checks):
        supporting.insert(0, "Local lists: not on any blacklist or feed")
    n_risk = len(concerns)
    trusted = any(c["state"] == "match" and c["effect"] == "trust" and c["id"] == "whitelist" for c in checks)
    if status == "Malicious":
        label, conf = "Dangerous", "high" if n_risk >= 2 else "medium"
        text = "Do not enter any information on this site. " + ("Several independent sources agree." if n_risk >= 2 else "The evidence comes mostly from one source.")
    elif status == "Suspicious":
        label, conf = "Suspicious: be careful", "medium"
        text = "Some warning signs were found but not enough to call the site malicious. Do not enter passwords or payment details unless you are sure it is the real site."
    elif status == "Safe" and trusted:
        label, conf, text = "Trusted site", "high", "A trusted list vouches for this site."
    elif status == "Safe":
        label, conf = ("Looks legitimate (established site)", "medium") if ctx.get("established") else ("Looks safe", "medium")
        text = ("It is an old, widely visited site and nothing reports it. This is strong evidence but not a guarantee: "
                "even real sites can be hacked, so still check the address before you log in.")
    elif score is None and not ctx.get("checked", False):
        label, conf = "Could not be checked", "low"
        text = "Too many sources could not be reached to say anything about this site. Try again later; until then treat it as unverified."
    else:
        label, conf = "No warning signs found", "low" if len(missing) >= 3 else "medium"
        text = ("Nothing reports this site and nothing on it looks dangerous, but nothing vouches for it either (it is not a well-known, "
                "long-running site), so it is not confirmed safe. Be careful with passwords and payments.")
    return {"label": label, "confidence": conf, "summary": text, "supporting": supporting, "concerns": concerns, "not_checked": missing}


def _final_block(status: str, score, checks: list[dict], list_api_score, ai_comb: dict, notes: list[str], ctx: dict | None = None) -> dict:
    api_text = _list_api_text(checks)
    asm = _assessment(status, score, checks, ai_comb, ctx or {})
    head = (f"{asm['label']}: {asm['summary']}" if score is None else f"Final risk {int(round(score))}/100 ({status}). {asm['label']}: {asm['summary']}")
    summary = " ".join([head, "Lists / APIs: " + api_text, "AI models: " + ai_comb["description"]]
                       + (["Combined: " + " ".join(notes)] if notes else []))
    return {"status": status, "score": score, "list_api": {"score": list_api_score, "text": api_text},
            "ai": {"score": ai_comb.get("score"), "text": ai_comb["description"]}, "notes": list(notes), "method": FINAL_METHOD,
            "assessment": asm, "summary": summary}


def _checked_reasons(checks: list[dict], existing: list[str]) -> list[str]:
    """One plain line per source that found nothing, so `reasons` shows which sources were used even when they were quiet.
    (Wording avoids 'unavailable' / 'could not be read': analyze() uses those words to retry partial results sooner.)"""
    out = []
    lists = [c for c in checks if c["group"] == "list"]
    if lists and all(c["state"] in ("clear", "skipped") for c in lists) and any(c["state"] == "clear" for c in lists):
        out.append("Local lists (blacklist, OpenPhish / URLhaus feed, adult-site list, trusted list): checked, no record found")
    for c in checks:
        if c["group"] == "api" and c["state"] == "clear":
            out.append(f"{c['name']}: checked, no record found")
        elif c["group"] == "rule" and c["state"] in ("clear", "info"):
            if not any(c["detail"] in r for r in existing):         # the rule may already have explained itself
                out.append(f"{c['name']}: {c['detail']}")
        elif c["state"] == "not_configured":
            out.append(f"{c['name']}: not configured (no API key), so it was not used")
        elif c["id"] == "domain_age" and c["state"] == "no_opinion":
            out.append(f"Domain age: {c['detail']}")
        elif c["id"] == "ai1" and c["state"] == "no_opinion":
            out.append(f"AI 1 (URL model): no opinion, {c['detail'].replace('No opinion: ', '')}")
    return out


def _result(url, status, score, source, reasons, pt=None, extra=None) -> dict:
    out = {
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
    if extra:
        out.update(extra)
    return out


def _by_list(url, status, score, source, reasons, ck: _Checks, why: str, category: str | None = None) -> dict:
    """A result decided by a local list: the APIs and the AI models were not needed, and are listed as skipped."""
    ck.skip_rest(why)
    extra = _ai_off(why)
    checks = ck.as_list()
    extra["checks"] = checks
    extra["final"] = _final_block(status, score, checks, score, extra["ai_combined"], [])
    r = _result(url, status, score, source, reasons, None, extra)
    if category:
        r["category"] = category
    return r


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
    ck = _Checks()

    # 1. Blacklist (highest priority)
    if reg in BLACKLIST_DOMAINS or host in BLACKLIST_DOMAINS:
        ck.add("blacklist", "match", "Domain is in the manual blacklist", 100, "risk")
        return _by_list(raw_url, "Malicious", 100, "blacklist", ["Domain is in the manual blacklist"], ck,
                        "Not needed: the manual blacklist already decided this result.")
    ck.add("blacklist", "clear", "Not in the manual blacklist")
    if _key(url) in FEED_URLS:
        ck.add("feed", "match", "URL is in the OpenPhish / URLhaus feed", 100, "risk")
        return _by_list(raw_url, "Malicious", 100, "blacklist", ["URL is in the OpenPhish / URLhaus feed"], ck,
                        "Not needed: the OpenPhish / URLhaus feed already decided this result.")
    ck.add("feed", "clear", "URL is not in the OpenPhish / URLhaus feed")

    # 1b. Adult content (before the Tranco whitelist: popular adult sites sit in the top 10,000 too)
    if BLOCK_ADULT and ADULT and reg not in MANUAL_WHITELIST and host not in MANUAL_WHITELIST and _is_adult(host):
        ck.add("adult", "match", "Adult content site (blocked by your adult-site list)", 100, "risk")
        return _by_list(raw_url, "Restricted", 100, "adult-list", ["Adult content site (blocked by your adult-site list)"], ck,
                        "Not needed: the adult-site list already decided this result.", category="adult")
    if not BLOCK_ADULT:
        ck.add("adult", "skipped", "Switched off (BLOCK_ADULT=0)")
    elif not ADULT:
        ck.add("adult", "skipped", "No adult-site list is loaded")
    else:
        ck.add("adult", "clear", "Not on the adult-site list")

    # 2. Whitelist (shared hosting platforms are excluded on purpose)
    if reg in WHITELIST and not is_shared(host):
        d = f"{reg} is a known trusted domain"
        ck.add("whitelist", "match", d, 5, "trust")
        return _by_list(raw_url, "Safe", 5, "whitelist", [d], ck, "Not needed: the site is on a trusted list.")

    # 2a. Endings only verified institutions can register (edu.my, gov.my ...)
    if TRUSTED_SUFFIXES and not is_shared(host) and ("." + reg).endswith(TRUSTED_SUFFIXES):
        d = f"{reg} uses a restricted institutional domain ending"
        ck.add("whitelist", "match", d, 10, "trust")
        return _by_list(raw_url, "Safe", 10, "trusted-suffix", [d], ck, "Not needed: the site uses a restricted institutional domain ending.")

    # 2b. Trusted application paths on shared hosts (e.g. your own Google Drive UI)
    if TRUSTED_PREFIXES and _key(url).startswith(TRUSTED_PREFIXES):
        ck.add("whitelist", "match", "Trusted application path", 5, "trust")
        return _by_list(raw_url, "Safe", 5, "whitelist", ["Trusted application path"], ck, "Not needed: the address is a trusted application path.")
    ck.add("whitelist", "clear", "Not on the trusted list" + (" (public hosting platforms are never trusted by domain)" if is_shared(host) else ""))

    # 3. PhishTank + Safe Browsing + look-alike + domain age + AI 1 + AI 2
    scores: list[float] = []
    reasons: list[str] = []
    pt = None

    shared = is_shared(host)
    pt = _phishtank(url)
    if pt.succeeded and shared and pt.match_scope == "domain":
        # on a public platform the "domain" is shared by thousands of unrelated sites
        reasons.append("PhishTank domain-level match ignored (public hosting platform)")
        ck.add("phishtank", "clear", "A domain-level record exists but was ignored: on a public hosting platform the domain is shared by thousands of sites")
        pt = None
    elif not pt.succeeded:
        log.warning("PhishTank lookup failed: %s", pt.error)
        reasons.append("PhishTank unavailable (lookup failed)")
        ck.add("phishtank", "unavailable", "The lookup failed, so PhishTank was not checked")
        pt = None
    elif pt.risk_contribution is not None:
        scores.append(pt.risk_contribution)
        reasons.append(f"PhishTank {pt.match_scope} match (phish_id {pt.phish_id})")
        ck.add("phishtank", "match", f"{'Exact page' if pt.match_scope == 'exact' else 'Domain-level'} match, phish_id {pt.phish_id}",
               pt.risk_contribution, "risk")
    elif pt.found:
        reasons.append("PhishTank record exists but was voted not-phishing")
        ck.add("phishtank", "clear", "A record exists but the community voted it not-phishing")
        pt = None
    else:
        ck.add("phishtank", "clear", "No record found")
        pt = None

    # Look-alike of a protected domain (typo / homoglyph / extra words); not meaningful on shared platforms
    la = None if shared else lookalike.check(host)
    la_score = LOOKALIKE_SCORE if la else None
    if la:
        la_score, la_notes, same_owner = _refine_lookalike(la, reg)
        if same_owner:
            la, la_score = None, None
            reasons.extend(la_notes)
            ck.add("lookalike", "clear", la_notes[0])
        else:
            scores.append(la_score)
            reasons.append(f"Look-alike domain: {la['reason']}. This does not prove it is malicious.")
            reasons.extend(la_notes)
            ck.add("lookalike", "match", f"{la['reason']}. " + " ".join(la_notes), la_score, "risk")
    elif shared:
        ck.add("lookalike", "skipped", "Not meaningful on public hosting platforms")
    else:
        ck.add("lookalike", "clear", "Does not look like a protected domain")

    # Google Safe Browsing (inactive unless GOOGLE_SAFE_BROWSING_API_KEY is set)
    sb = _safebrowsing(url)
    sb_score = sb.risk_contribution
    if not sb.configured:
        ck.add("safebrowsing", "not_configured", "No API key is set (GOOGLE_SAFE_BROWSING_API_KEY in AIDev/.env), so Google Safe Browsing was not used")
    elif not sb.succeeded:
        log.warning("Safe Browsing lookup failed: %s", sb.error)
        reasons.append("Google Safe Browsing unavailable (lookup failed)")
        ck.add("safebrowsing", "unavailable", "The lookup failed, so Google Safe Browsing was not checked")
    elif sb_score is not None:
        scores.append(sb_score)
        reasons.append(f"Google Safe Browsing lists this URL ({sb.threat_type})")
        ck.add("safebrowsing", "match", f"Google lists this URL as {sb.threat_type}", sb_score, "risk")
    else:
        ck.add("safebrowsing", "clear", "Google has no record of this URL (new pages can take time to be listed)")

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
    api_parts = list(non_ml)                           # evidence from lists / APIs / domain rules only (no AI), for `final`

    if shared:
        if max(scores, default=0) < 60:               # no confirmed evidence: explain the mild warning
            reasons.append("Hosted on a public platform where anyone can publish. "
                           "This alone does not mean the page is malicious.")
        scores.append(THRESHOLD_SUSPICIOUS)          # mild warning floor, far below Malicious
        non_ml.append(THRESHOLD_SUSPICIOUS)
        api_parts.append(THRESHOLD_SUSPICIOUS)

    score = max(scores, default=None)

    # Domain age for every site that no list knows about. Phishing domains are mostly days old, whatever
    # their name looks like, so this works where the URL text (model) and look-alike rules see nothing.
    # Old domain + only a weak model suspicion -> relax. Lookup failure (or a ccTLD without RDAP) changes nothing.
    age_new = False
    age_days = None
    age_kind = None
    rank_ = None
    wd_ = cert_ = None
    if not shared and la_score is None and max(non_ml, default=0) < 60:
        with ThreadPoolExecutor(max_workers=3) as ex:                  # three independent look-ups, asked at the same time
            f_age, f_cert, f_wd = ex.submit(domain_age.lookup, reg), ex.submit(cert_history.lookup, reg), ex.submit(official_site.lookup, reg, host)
            ai_, cert_, wd_ = f_age.result(), f_cert.result(), f_wd.result()
        age_days = ai_.days if ai_.succeeded else None
        age_kind = ai_.kind
        via = {"rdap": "RDAP", "whois": "WHOIS", "archive": "the Internet Archive"}.get(ai_.method or "", "")
        old_enough = age_days is not None and age_days >= (730 if age_kind == "registered" else 1095)
        if age_days is not None and age_kind == "registered" and age_days < 30 and not non_ml:
            age_new = True
            score = max(score or 0, 55 if (ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS) else 45)
            non_ml.append(45)
            api_parts.append(45)
            reasons.append(f"Domain was registered only {age_days} days ago and is on no list (new domains are common in phishing)")
            ck.add("domain_age", "match", f"Registered only {age_days} days ago ({via}) and on no list (new domains are common in phishing)", 45, "risk")
        elif old_enough and not non_ml and score is not None and score >= THRESHOLD_SUSPICIOUS:
            score = THRESHOLD_SUSPICIOUS - 1
            reasons.append(f"Domain is at least {age_days // 365} years old, which outweighs the model's weak suspicion")
            ck.add("domain_age", "info", f"At least {age_days // 365} years old ({via}), which outweighs the model's weak suspicion")
        elif age_days is not None and age_kind == "registered":
            ck.add("domain_age", "info", f"Registered {_age_text(age_days)} ago ({via})")
        elif age_days is not None:
            ck.add("domain_age", "info", f"At least {_age_text(age_days)} old: the Internet Archive first saved this site "
                                         f"{ai_.created:%Y-%m-%d}. The registration date itself could not be found ({ai_.note.split('(', 1)[-1].rstrip(')')})")
        else:
            ck.add("domain_age", "no_opinion", f"No registration date found. {ai_.note[:1].upper() + ai_.note[1:]}.")
        if not cert_.succeeded:
            ck.add("certs", "no_opinion", "Certificate history could not be read (crt.sh busy or offline, and the site's certificate could not be read)")
        else:
            bits = []
            if cert_.first_seen is not None:
                bits.append(f"first HTTPS certificate {cert_.first_seen:%Y-%m-%d} ({_age_text(cert_.days)} ago), {cert_.n_certs} certificate(s)"
                            + (f" from {', '.join(cert_.issuers[:3])}" if cert_.issuers else ""))
            else:
                bits.append("no certificate history found")
            bits.append(f"the site's certificate names the organisation '{cert_.org}' (the issuer checked who is behind the site)" if cert_.org
                        else "the site's certificate names no organisation (a free / domain-only certificate)")
            ck.add("certs", "info", (lambda t: t[:1].upper() + t[1:])("; ".join(bits)))
        if not wd_.succeeded:
            ck.add("wikidata", "no_opinion", "Wikidata did not answer")
        elif wd_.found:
            who = wd_.label or wd_.qid
            ck.add("wikidata", "match", f"Wikidata lists this domain as the official website of '{who}'" + (f" ({wd_.description})" if wd_.description else ""), 10, "trust")
        else:
            ck.add("wikidata", "info", "No Wikidata entry lists this domain as an official website (normal for small or local sites; it says nothing against the site)")
        rank_ = popularity.rank(reg)
        if rank_ is not None:
            ck.add("popularity", "info", f"Rank #{rank_:,} among the 300,000 most visited websites (Tranco). Throw-away phishing domains are never this popular.")
        elif popularity.available():
            ck.add("popularity", "info", "Not among the 300,000 most visited websites (normal for small or local sites)")
        else:
            ck.add("popularity", "no_opinion", "The Tranco list file (AIDev/data/tranco_top.txt) is missing, so popularity was not checked")
    elif shared:
        ck.add("domain_age", "skipped", "Not used on public hosting platforms (the domain belongs to the platform)")
        ck.add("popularity", "skipped", "Not used on public hosting platforms")
        ck.add("certs", "skipped", "Not used on public hosting platforms")
        ck.add("wikidata", "skipped", "Not used on public hosting platforms")
    elif la_score is not None:
        ck.add("domain_age", "skipped", "Already used inside the look-alike check")
        ck.add("popularity", "skipped", "Not needed: the look-alike check already has evidence about this site")
        ck.add("certs", "skipped", "Not needed: the look-alike check already has evidence about this site")
        ck.add("wikidata", "skipped", "Not needed: the look-alike check already has evidence about this site")
    else:
        ck.add("domain_age", "skipped", "Not needed: a list or API already has evidence about this site")
        ck.add("popularity", "skipped", "Not needed: a list or API already has evidence about this site")
        ck.add("certs", "skipped", "Not needed: a list or API already has evidence about this site")
        ck.add("wikidata", "skipped", "Not needed: a list or API already has evidence about this site")

    # Page content: download the page and read it. Skipped when a list already says Malicious (saves time) and on shared
    # platforms (training data has none). The same download also shows whether the address is a program-file download
    # or the page starts one by itself, which works even when the content model is not trained.
    content = None
    content_score = None
    download_score = None
    download_direct = None
    ai2_skip = None
    if shared:
        ai2_skip = "Skipped: this is a public hosting platform, and the page model was not trained on such pages."
    elif max([x for x in (pt_score, sb_score) if x is not None], default=0) >= 70:
        ai2_skip = "Skipped: a list or API already says this URL is malicious, so the page was not downloaded."
    elif not predict_content.enabled():
        ai2_skip = "Switched off (CONTENT_CHECK=0)."
    else:
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
                    reasons.extend(("Page" + s_[4:]) if s_.startswith("page ") else f"Page {s_}" for s_ in content["signals"][:3])
                    non_ml.append(content_score)
        else:
            reasons.append("Page content could not be read (unreachable, not plain HTML, or built by JavaScript)")

    ai2_score = max([x for x in (content_score, download_score) if x is not None], default=None)
    ai1 = _ai1_block(ml, ml_score, shared)
    ai2 = _ai2_block(content, ai2_score, ai2_skip)
    ai_comb = _ai_combined(ml_score, ai2_score)
    ck.add("ai1", "no_opinion" if ml_score is None else "match" if ml_score >= THRESHOLD_SUSPICIOUS else "clear",
           f"Phishing probability {ai1['percent']}%" if ml is not None else f"No opinion: {_ai1_why()}",
           ml_score, "risk" if ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS else "none")
    if ai2["state"] == "ok":
        hot = [c for c in ai2["categories"] if c["triggered"]]
        ai2_hit = (ai2_score is not None and ai2_score >= THRESHOLD_SUSPICIOUS) or bool(download_direct)
        ck.add("ai2", "match" if ai2_hit else "clear",
               (f"Phishing probability {ai2['percent']}%" if ai2["percent"] is not None else "Page read, no probability from the model")
               + (" · " + ", ".join(f"{c['label']} {c['percent']}%" for c in hot) if hot else ""),
               ai2_score, "risk" if ai2_hit else "none")
    else:
        ck.add("ai2", ai2["state"], ai2["description"].replace(AI2_BASE + " ", ""))

    notes: list[str] = []                                  # which "independent signals agree" rules fired, for the summary

    def agree(text: str) -> None:
        reasons.append(text)
        notes.append(text)

    # Two independent sources agreeing is stronger than either one: a PhishTank record that is not yet
    # voted on (60) plus a model that also finds the URL suspicious is treated as Malicious.
    if pt_score is not None and pt_score >= 60 and ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS:
        score = max(score, THRESHOLD_MALICIOUS)
        agree("PhishTank record and ML model agree")

    # A look-alike name that the model also finds suspicious: two independent weak signals agree.
    if content_score is not None and content_score >= THRESHOLD_SUSPICIOUS and (
            age_new or la_score is not None or (ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS)
            or (pt_score is not None and pt_score >= 60)):
        score = max(score, THRESHOLD_MALICIOUS)
        agree("Page content and another independent signal agree")

    if la_score is not None and ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS:
        score = max(score, THRESHOLD_MALICIOUS)
        agree("Look-alike domain and ML model agree")

    # Downloads: a program file pushed by the page, or served straight from the address, together with another warning sign.
    strong_other = age_new or la_score is not None or (pt_score is not None and pt_score >= 60)
    if download_direct and strong_other:
        score = max(score or 0, THRESHOLD_MALICIOUS)
        agree("Program-file download from a site that also shows another warning sign")
    if download_score is not None and (strong_other
                                       or (content_score is not None and content_score >= THRESHOLD_SUSPICIOUS)
                                       or (ml_score is not None and ml_score >= THRESHOLD_SUSPICIOUS)):
        score = max(score, THRESHOLD_MALICIOUS)
        agree("Automatic download and another independent signal agree")

    # Established site: old AND widely visited AND nothing reported anywhere. Phishing sites live for days and nobody visits them,
    # so this is positive evidence (not just "nothing found"). Off with ESTABLISHED_SAFE=0.
    established = False
    cert_days = cert_.days if (cert_ is not None and cert_.succeeded) else None
    old_ok = age_days is not None and age_days >= (730 if age_kind == "registered" else 1095)
    official = wd_ is not None and wd_.succeeded and wd_.found and ((age_days or 0) >= 365 or (cert_days or 0) >= 365)
    quiet = (ESTABLISHED_SAFE and not shared and not non_ml and not download_direct and (score is None or score < THRESHOLD_SUSPICIOUS)
             and not (ai2["state"] == "ok" and any(c["triggered"] for c in ai2["categories"])))
    if quiet and ((rank_ is not None and old_ok) or official):
        established = True
        score = 15 if score is None else max(score, 15)
        if rank_ is not None and old_ok:
            ck.add("popularity", "match", f"Rank #{rank_:,} of 300,000 and at least {age_days // 365} years old, with nothing reported: an established site", 15, "trust")
            reasons.append(f"Established site: at least {age_days // 365} years old, rank #{rank_:,} among the most visited sites, "
                           "and no list, API or model reports anything")
        if official:
            reasons.append(f"Official website of '{wd_.label or wd_.qid}' according to Wikidata, the domain is not new, and nothing reports it")

    list_api_score = max(api_parts, default=None)

    def finish(status: str, final_score, source: str, pt_for_result=None) -> dict:
        checks = ck.as_list()
        reasons.extend(_checked_reasons(checks, reasons))
        extra = {"checks": checks, "ai1": ai1, "ai2": ai2, "ai_combined": ai_comb,
                 "final": _final_block(status, final_score, checks, list_api_score, ai_comb, notes, {"established": established, "checked": score is not None})}
        return _result(raw_url, status, final_score, source, reasons, pt_for_result, extra)

    if score is None:
        reasons[:] = reasons or ["No data from any source"]
        return finish("Unknown", None, "none")

    # "Safe" must rest on evidence of safety. A model that merely sees nothing suspicious cannot
    # vouch for a site (e.g. a phishing page on a normal-looking domain), so that case is Unknown.
    if established and _status(score) == "Safe":
        return finish("Safe", score, "established-site")
    if _status(score) == "Safe" and not non_ml:
        reasons.append("No strong phishing signal from the model. This is not a guarantee that the site is safe.")
        return finish("Unknown", None, "model")

    source = "+".join(n for n, on in (("phishtank", pt is not None), ("safebrowsing", sb_score is not None),
                                      ("lookalike", la_score is not None), ("domain-age", age_new), ("content", content_score is not None),
                                      ("download", download_score is not None or download_direct is not None),
                                      ("model", ml is not None)) if on) or "shared-host"
    return finish(_status(score), score, source, pt)
