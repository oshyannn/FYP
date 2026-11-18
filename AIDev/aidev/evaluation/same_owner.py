"""
Decide whether two domains that serve similar pages probably belong to the SAME owner. Own rules, stdlib only.

    from aidev.evaluation.same_owner import same_owner
    res = same_owner("shopee.sg", html_a, "shopee.com", html_b)
    res["verdict"]   # "same" | "different" | "unknown"
    res["evidence"]  # list of human-readable reasons

Verdicts:
  "same"      strong evidence: one page links to the other domain, or both show the same copyright owner text.
  "different" only when the registrant organisation is known for BOTH domains (rdap_org callback) and the two differ.
  "unknown"   no decision. Absence of evidence is NOT treated as "different".

Use: to clean the background / reference set (drop same-owner pairs before judging clone similarity), and for the
report. Never use a verdict to label a domain as malicious or to report it.

Limits: copyright lines can be shared by agencies or templates; registrant data is often a privacy proxy (ignored here).
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urlsplit

COPY_RE = re.compile(r"(?:©|&copy;|copyright)\s*(?:\d{4}\s*[-–]?\s*\d{0,4})?\s*([^<\n\r|]{3,80})", re.I)
STOP = {"all", "rights", "reserved", "inc", "ltd", "llc", "pte", "co", "corp", "the", "and", "limited", "company",
        "group", "com", "net", "org", "by", "for", "with"}
PROXY_WORDS = ("proxy", "privacy", "redacted", "withheld", "whoisguard", "domains by", "contact privacy")


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k in ("href", "src") and v:
                self.urls.append(v)


def _hosts(html: str) -> set[str]:
    p = _Links()
    try:
        p.feed(html or "")
    except Exception:
        pass
    hosts = set()
    for u in p.urls:
        try:
            h = urlsplit(u).hostname
        except ValueError:
            h = None
        if h:
            hosts.add(h.lower())
    return hosts


def links_to(html: str, domain: str) -> bool:
    """True if the page links or loads a resource from `domain` or a subdomain of it."""
    d = (domain or "").lower()
    return any(h == d or h.endswith("." + d) for h in _hosts(html))


def copyright_owners(html: str) -> set[str]:
    """Word tokens from the first copyright lines, e.g. '© 2024 Shopee Pte Ltd.' -> {'shopee'}."""
    tokens: set[str] = set()
    for m in list(COPY_RE.finditer(html or ""))[:3]:
        for w in re.findall(r"[a-zA-Z][a-zA-Z0-9]{2,}", m.group(1).lower()):
            if w not in STOP:
                tokens.add(w)
    return tokens


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


def _org_norm(org: str) -> str:
    return re.sub(r"[^a-z0-9]", "", org.lower())


def same_owner(dom_a: str, html_a: str, dom_b: str, html_b: str,
               rdap_org: Callable[[str], str | None] | None = None) -> dict:
    evidence: list[str] = []
    if links_to(html_a, dom_b):
        evidence.append(f"page of {dom_a} links to {dom_b}")
    if links_to(html_b, dom_a):
        evidence.append(f"page of {dom_b} links to {dom_a}")
    oa, ob = copyright_owners(html_a), copyright_owners(html_b)
    if _jaccard(oa, ob) >= 0.5:
        evidence.append(f"same copyright owner text: {sorted(oa & ob)[:5]}")
    if evidence:
        return {"verdict": "same", "evidence": evidence}

    if rdap_org is not None:
        ra, rb = rdap_org(dom_a), rdap_org(dom_b)
        usable = lambda o: bool(o) and not any(w in o.lower() for w in PROXY_WORDS)
        if usable(ra) and usable(rb):
            if _org_norm(ra) == _org_norm(rb):
                return {"verdict": "same", "evidence": [f"same registrant organisation: {ra}"]}
            return {"verdict": "different", "evidence": [f"registrant organisations differ: {ra} / {rb}"]}
        return {"verdict": "unknown", "evidence": ["registrant hidden or missing for one domain"]}

    return {"verdict": "unknown", "evidence": ["no shared link or copyright owner found"]}


if __name__ == "__main__":
    a = '<a href="https://shopee.com/x">x</a><footer>© 2024 Shopee Pte Ltd</footer>'
    b = '<footer>© 2024 Shopee Pte Ltd. All rights reserved.</footer>'
    c = '<footer>© 2024 Example Travel Co</footer>'
    print(same_owner("shopee.sg", a, "shopee.com", b))
    print(same_owner("shopee.sg", b, "example.org", c))
