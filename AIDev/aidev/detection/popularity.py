"""
How popular a domain is, from the Tranco list (the same list the trusted-list check uses): rank 1 = most visited.

    from aidev.detection.popularity import rank
    rank("sinchew.com.my")      # e.g. 41872, or None when the domain is not in the list (or the list file is missing)

Why it matters: phishing domains live for days and nobody visits them, so they are never in the top 300,000 sites.
A domain that is both OLD and widely visited is very unlikely to be a throw-away phishing site. Being popular does not make
a site safe (compromised popular sites exist), so detector.py only uses it together with age and only when nothing is reported.
"""
from __future__ import annotations

from aidev.core.common import DATA, lines

LIMIT = 300_000
_RANKS: dict[str, int] | None = None


def _load() -> dict[str, int]:
    global _RANKS
    if _RANKS is None:
        _RANKS = {d: i + 1 for i, d in enumerate(lines(DATA / "tranco_top.txt")[:LIMIT])}
    return _RANKS


def available() -> bool:
    return bool(_load())


def rank(registered_domain: str) -> int | None:
    return _load().get((registered_domain or "").lower())
