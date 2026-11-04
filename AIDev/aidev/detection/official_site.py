"""
Official-website cross-check with Wikidata: is this domain the official website of a known organisation?

    from aidev.detection.official_site import lookup
    o = lookup("sinchew.com.my", "www.sinchew.com.my")     # OfficialInfo: found, label, description, qid

Wikidata is edited by thousands of independent volunteers and lists the "official website" (property P856) of newspapers, banks,
companies, universities and government bodies. If an entry names THIS domain as its official website, someone independent of this
project and of every blacklist has vouched that the domain belongs to that organisation. A phishing site cannot appear there.
Honest limits: small or new organisations have no entry, so "not found" says nothing against a site. Wikidata can be vandalised
(rarely, and quickly reverted), so detector.py uses a match together with domain age and never alone. A match proves who owns the
DOMAIN, not that a page under it is harmless (a hacked real site stays real). Only the domain name is sent.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import requests

API = "https://www.wikidata.org/w/api.php"
HEADERS = {"User-Agent": "FYP-PhishingDetector/1.0 (student project; official-site check)"}


@dataclass(frozen=True)
class OfficialInfo:
    succeeded: bool
    found: bool = False
    qid: str | None = None
    label: str | None = None
    description: str | None = None
    error: str | None = None


def variants(reg: str, host: str) -> list[str]:
    """Spellings of the address that Wikidata editors use for P856."""
    hosts = list(dict.fromkeys(h for h in (host, reg, "www." + reg) if h))
    out = []
    for h in hosts:
        for scheme in ("https", "http"):
            out += [f"{scheme}://{h}/", f"{scheme}://{h}"]
    return out


def parse_search(text: str) -> list[str]:
    """Pure function (testable offline): list=search answer -> entity ids (Q...)."""
    try:
        rows = json.loads(text).get("query", {}).get("search", [])
    except (ValueError, AttributeError):
        return []
    return [r["title"] for r in rows if isinstance(r, dict) and str(r.get("title", "")).startswith("Q")]


def parse_entity(text: str, qid: str) -> tuple[str | None, str | None]:
    """Pure function: wbgetentities answer -> (English label, English description)."""
    try:
        e = json.loads(text)["entities"][qid]
        return (e.get("labels", {}).get("en", {}).get("value"), e.get("descriptions", {}).get("en", {}).get("value"))
    except (ValueError, KeyError, TypeError):
        return None, None


def _search(url: str, timeout: float):
    r = requests.get(API, params={"action": "query", "list": "search", "srsearch": f"haswbstatement:P856={url}", "srlimit": 3,
                                  "format": "json"}, headers=HEADERS, timeout=timeout)
    if r.status_code != 200:
        raise requests.RequestException(f"HTTP {r.status_code}")
    return parse_search(r.text)


_cache: dict[tuple[str, str], tuple[float, OfficialInfo]] = {}


def lookup(reg: str, host: str, timeout: float = 5.0) -> OfficialInfo:
    key = (reg, host)
    now = time.time()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    info = _lookup(reg, host, timeout)
    _cache[key] = (now + (86400 if info.succeeded else 300), info)
    return info


def _lookup(reg: str, host: str, timeout: float) -> OfficialInfo:
    urls = variants(reg, host)
    ids, failed = [], 0
    with ThreadPoolExecutor(max_workers=6) as ex:
        for f in [ex.submit(_search, u, timeout) for u in urls]:
            try:
                ids += f.result()
            except requests.RequestException:
                failed += 1
    if not ids:
        if failed == len(urls):
            return OfficialInfo(False, error="Wikidata did not answer")
        return OfficialInfo(True, found=False)
    qid = ids[0]
    label = desc = None
    try:
        r = requests.get(API, params={"action": "wbgetentities", "ids": qid, "props": "labels|descriptions", "languages": "en", "format": "json"},
                         headers=HEADERS, timeout=timeout)
        label, desc = parse_entity(r.text, qid)
    except requests.RequestException:
        pass
    return OfficialInfo(True, True, qid, label, desc)
