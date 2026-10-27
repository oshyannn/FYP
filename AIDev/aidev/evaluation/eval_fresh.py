"""
Honest check of the MODEL on phishing it has never seen.

    python feeds.py              # refresh feeds (OpenPhish/URLhaus change daily)
    python eval_fresh.py         # BEFORE retraining; --benign my_sites.txt adds a false-positive check

"Fresh" = phishing URLs from the feeds whose registered domain is not in data/dataset.csv at all, so the
model cannot have memorised them. Only the model is evaluated (blacklist/PhishTank/Safe Browsing would
trivially catch listed URLs). Do not retrain between refreshing the feeds and running this, or the
URLs stop being fresh.

--benign FILE: text file, one legitimate URL per line (not used in training), to measure false positives.
"""
from __future__ import annotations

import argparse
import random

import pandas as pd

from common import DATA, lines
from features import registered_domain
from predict import predict

THRESHOLDS = (0.5, 0.7, 0.9)


def _probs(urls):
    out = []
    for u in urls:
        r = predict(u)
        if r is not None:
            out.append(r["probability"])
    return out


def _rates(p, label):
    n = len(p)
    if not n:
        print(f"  {label}: no usable URLs")
        return
    print(f"  {label}: n={n}  " + "  ".join(f"flagged@{t}: {sum(x >= t for x in p) / n:.1%}" for t in THRESHOLDS))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", help="file with legitimate URLs, one per line")
    ap.add_argument("--n", type=int, default=2000, help="max fresh phishing URLs to test")
    a = ap.parse_args()

    train = pd.read_csv(DATA / "dataset.csv")
    seen_domains = set(train["group"])

    cand = lines(DATA / "feeds_urls.txt")
    for f in sorted(DATA.glob("phishing_*.csv")):
        cand += [str(u).strip().lower() for u in pd.read_csv(f)["url"].dropna()]
    fresh = []
    for u in sorted(set(cand)):
        try:
            if registered_domain(u) not in seen_domains:
                fresh.append(u)
        except Exception:
            pass
    print(f"fresh phishing URLs (domain never in the training data): {len(fresh)}")
    if len(fresh) < 50:
        print("  Too few to mean anything. Run `python feeds.py` again later and do not retrain in between.")
    random.Random(1).shuffle(fresh)
    print("model on fresh phishing (higher is better; this is recall):")
    _rates(_probs(fresh[: a.n]), "fresh phishing")

    if a.benign:
        print("model on your legitimate URLs (lower is better; this is the false-positive rate):")
        _rates(_probs(lines(__import__("pathlib").Path(a.benign))), "legitimate    ")
    else:
        print("(no --benign file given, so false positives were not measured)")


if __name__ == "__main__":
    main()
