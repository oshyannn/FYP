"""
Measure the look-alike check on YOUR data:  python -m aidev.evaluation.eval_lookalike

  false alarms : legitimate domains from Tranco ranks (TOP_N+1 .. +LIMIT), which are NOT protected,
                 that get flagged as imitating a protected one.  Lower is better.
  detections   : registered domains from the phishing feeds that get flagged.  Higher is better.

The examples printed show exactly what the rule is doing, so you can judge it and tune
LOOKALIKE_TOP_N / MIN_LEN_* in lookalike.py.
"""
from __future__ import annotations

import random
from collections import Counter

import pandas as pd

from aidev.detection import lookalike
from aidev.core.common import DATA, lines
from aidev.core.features import get_host

LIMIT = 25000


def _run(hosts):
    kinds, ex = Counter(), []
    for h in hosts:
        r = lookalike.check(h)
        if r:
            kinds[r["kind"]] += 1
            ex.append((h, r["kind"], r["target"]))
    return kinds, ex


def main() -> None:
    ranked = lines(DATA / "tranco_top.txt")
    benign = ranked[lookalike.LOOKALIKE_TOP_N: lookalike.LOOKALIKE_TOP_N + LIMIT]
    kinds, ex = _run(benign)
    n = max(len(benign), 1)
    print(f"false alarms on {len(benign)} legitimate domains: {sum(kinds.values())} ({sum(kinds.values()) / n:.2%})  {dict(kinds)}")
    for h, k, t in random.Random(1).sample(ex, min(12, len(ex))):
        print(f"    {h:34} {k:10} ~ {t}")

    urls = lines(DATA / "feeds_urls.txt")
    for f in sorted(DATA.glob("phishing_*.csv")):
        urls += [str(u).strip().lower() for u in pd.read_csv(f)["url"].dropna()]
    hosts = sorted({get_host(u) for u in urls if get_host(u)})
    random.Random(2).shuffle(hosts)
    hosts = hosts[:LIMIT]
    kinds, ex = _run(hosts)
    n = max(len(hosts), 1)
    print(f"\ndetections on {len(hosts)} phishing domains: {sum(kinds.values())} ({sum(kinds.values()) / n:.2%})  {dict(kinds)}")
    for h, k, t in random.Random(3).sample(ex, min(12, len(ex))):
        print(f"    {h:34} {k:10} ~ {t}")
    print("\nA hit means 'imitates a known domain', not 'malicious'. Compare the two rates before trusting the rule.")


if __name__ == "__main__":
    main()
