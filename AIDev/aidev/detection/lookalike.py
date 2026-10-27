"""
Look-alike (typosquatting) detection: is this domain imitating a domain we know to be real?

Protected domains = the most popular domains (Tranco top LOOKALIKE_TOP_N) + lists/protected_domains.txt
(yours: banks, services, your university...). A domain that is NOT itself protected but resembles one is
reported. Four patterns:

  typo        one edit away:  paypall.com, gooogle.com, charterbank.com vs chartersbank.com
  homoglyph   visually same:  paypa1.com (1 for l), arnazon.com (rn for m), Cyrillic letters in an IDN
  combo       real name plus filler words:  paypal-secure-login.com
  tld         real name on another (risky) domain ending:  maybank2u.xyz

Limits (be honest about them in the report):
  * It can only catch imitations of domains in the protected list. A fake that looks "valid" but imitates
    nothing we know is invisible here.
  * It says "looks like X", not "is malicious": legitimate, unrelated companies also have similar names,
    so a hit is a Suspicious-level signal, never Malicious on its own.
  * Pure lexical: no network, no WHOIS, no domain age.
"""
from __future__ import annotations

from functools import lru_cache

from common import DATA, LISTS, lines
import features
from features import RISKY_TLDS

LOOKALIKE_TOP_N = 5000        # popular domains used as the protected set
COMBO_TOP_N = 1000            # combo/filler matching only against the very top (fewer false alarms)
MIN_LEN_POPULAR = 6           # shorter popular names collide with unrelated real sites
MIN_LEN_MANUAL = 2           # your own list may hold short names (hi.com); popular ones stay >= 6

# characters that look alike; Cyrillic/Greek letters are the usual IDN homograph tricks
_CHARS = {
    "0": "o", "1": "l", "i": "l", "5": "s", "3": "e", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s", "і": "l", "ј": "j",
    "ԁ": "d", "ɡ": "g", "ο": "o", "ν": "v", "α": "a", "ε": "e", "ι": "l", "κ": "k", "ρ": "p", "τ": "t",
}
_TABLE = str.maketrans(_CHARS)


_TWO_LEVEL = {"com.my", "edu.my", "gov.my", "org.my", "net.my", "co.uk", "org.uk", "ac.uk", "com.au", "net.au",
              "co.jp", "co.id", "com.sg", "com.hk", "com.cn", "co.in", "co.nz", "com.br", "com.tr", "co.za"}


def split_host(host: str) -> tuple[str, str, str]:
    """(subdomain, registered domain, suffix). Uses tldextract when installed; otherwise handles common
    two-level endings such as .com.my itself, because the simple fallback in features.py cannot."""
    if features._EXTRACT is None:
        parts = host.split(".")
        if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_LEVEL:
            return ".".join(parts[:-3]), ".".join(parts[-3:]), ".".join(parts[-2:])
    return features.split_host(host)


def skeleton(label: str) -> str:
    """Collapse look-alike characters so that visually equal labels compare equal."""
    return label.lower().replace("rn", "m").replace("vv", "w").translate(_TABLE)


def _decode_idn(host: str) -> str:
    out = []
    for part in host.split("."):
        if part.startswith("xn--"):
            try:
                part = part.encode("ascii").decode("idna")
            except Exception:
                pass
        out.append(part)
    return ".".join(out)


def _label(reg: str, suffix: str) -> str:
    return reg[: -(len(suffix) + 1)] if suffix and reg.endswith("." + suffix) else reg


def within_one_edit(a: str, b: str) -> bool:
    """True if a and b differ by exactly one substitution, insertion, deletion or adjacent swap."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


class _Protected:
    """Protected domains plus lookup indexes, so one check costs a handful of dict lookups, not a scan."""

    def __init__(self) -> None:
        self.domains: set[str] = set()
        self.by_label: dict[str, list] = {}
        self.by_skel: dict[str, list] = {}
        self.by_deletion: dict[str, list] = {}
        manual = lines(LISTS / "protected_domains.txt")
        popular = lines(DATA / "tranco_top.txt")[:LOOKALIKE_TOP_N]
        seen: set[str] = set()
        for dom, is_manual in [(d, True) for d in manual] + [(d, False) for d in popular]:
            if dom in seen:
                continue
            seen.add(dom)
            _, reg, suffix = split_host(dom)
            if not reg:
                continue
            self.domains.add(reg)
            label = _label(reg, suffix)
            if len(label) < (MIN_LEN_MANUAL if is_manual else MIN_LEN_POPULAR):
                continue
            combo_ok = is_manual or len(seen) <= len(manual) + COMBO_TOP_N
            if suffix.split('.')[0] in {'gov', 'edu', 'ac', 'go', 'mil'} and '.' in suffix and not is_manual:
                combo_ok = False                   # service.gov.uk matches any '...-service-...' domain
            entry = (len(seen), label, reg, is_manual, combo_ok)       # first element = priority (manual first)
            self.by_label.setdefault(label, []).append(entry)
            self.by_skel.setdefault(skeleton(label), []).append(entry)
            for v in {label} | {label[:i] + label[i + 1:] for i in range(len(label))}:
                self.by_deletion.setdefault(v, []).append(entry)


_P: _Protected | None = None


def _protected() -> _Protected:
    global _P
    if _P is None:
        _P = _Protected()
    return _P


@lru_cache(maxsize=8192)
def check(host: str) -> dict | None:
    """
    host: any host name. Returns {"kind", "target", "reason"} if it imitates a protected domain, else None.
    Never raises.
    """
    try:
        p = _protected()
        host = _decode_idn(host.lower().strip("."))
        if host.startswith("www."):
            host = host[4:]
        _, reg, suffix = split_host(host)
        if not reg or reg in p.domains:
            return None                                   # it IS a protected domain (or empty)
        q = _label(reg, suffix)
        if len(q) < 3:
            return None

        # same name, different ending (maybank2u.xyz): meaningful for your own list or risky endings
        for _, label, dom, manual, _c in p.by_label.get(q, []):
            if len(q) < 4 and not manual:
                continue
            if manual or suffix.split(".")[-1] in RISKY_TLDS:
                return _hit("tld", dom, f"same name as {dom} but a different domain ending")

        # visually identical after collapsing look-alike characters
        for _, label, dom, manual, *_r in sorted(p.by_skel.get(skeleton(q), [])):
            if label != q and (len(q) >= 5 or manual):
                return _hit("homoglyph", dom, f"looks identical to {dom} (look-alike characters)")

        # one edit away (substitution, insertion, deletion, adjacent swap)
        # Short names (hi -> hii) are only compared with YOUR list: among popular domains, one-letter
        # neighbours of short names are usually unrelated real sites.
        short = len(q) < 5
        cands = {}
        for v in {q} | {q[:i] + q[i + 1:] for i in range(len(q))}:
            for e in p.by_deletion.get(v, []):
                if not short or e[3]:
                    cands[e[2]] = e
        if True:
            for _, label, dom, manual, *_r in sorted(cands.values()):
                # For popular (non-manual) targets, require plain letters and length >= 7: numbered
                # infrastructure names (awsdns-41 / awsdns-11, sf-cdn / sc-cdn) and short words are
                # one edit apart all the time without imitating anything.
                if not manual and (len(q) < 7 or not (q.isalpha() and label.isalpha())):
                    continue
                if within_one_edit(q, label):
                    return _hit("typo", dom, f"one character away from {dom}")

        # real name plus filler words (paypal-secure-login)
        tokens = [t for t in q.split("-") if t]
        if len(tokens) > 1:
            for t in tokens:
                if len(t) >= MIN_LEN_POPULAR or t in {e[1] for e in p.by_label.get(t, []) if e[3]}:
                    for _, label, dom, manual, combo_ok in p.by_label.get(t, []):
                        if combo_ok and label != q:
                            return _hit("combo", dom, f"contains the name of {dom} with extra words")
        return None
    except Exception:
        return None


def _hit(kind: str, target: str, reason: str) -> dict:
    return {"kind": kind, "target": target, "reason": reason}
