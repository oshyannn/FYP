"""
Own evaluation functions for model 1 (numpy + pandas only, nothing taken from other projects).

  roc_auc, average_precision (PR-AUC)      ranking quality
  threshold_at_fpr / rates_at              pick a threshold from a false-positive budget, then measure it
  recall_at_fpr                            "how many phishing URLs do we catch if only X% of good URLs may be flagged"
  bootstrap_ci                             95% interval, resampling whole domains (not single URLs)
  brier / calibration_table                are the probabilities honest?

Decision rule everywhere: flagged  <=>  score >= threshold.
"""
from __future__ import annotations

import numpy as np
import pandas as pd


def roc_auc(y, s) -> float:
    """Probability that a random phishing URL scores higher than a random benign one (ties count half)."""
    y = np.asarray(y)
    s = np.asarray(s, dtype=float)
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    if pos == 0 or neg == 0:
        return float("nan")
    ranks = pd.Series(s).rank(method="average").to_numpy()
    return float((ranks[y == 1].sum() - pos * (pos + 1) / 2) / (pos * neg))


def average_precision(y, s) -> float:
    """PR-AUC as average precision: sum over distinct scores of (recall gained) x (precision there)."""
    y = np.asarray(y)
    s = np.asarray(s, dtype=float)
    total_pos = int((y == 1).sum())
    if total_pos == 0:
        return float("nan")
    order = np.argsort(-s, kind="mergesort")
    ys, ss = y[order], s[order]
    tp = np.cumsum(ys == 1)
    fp = np.cumsum(ys == 0)
    last = np.r_[ss[1:] != ss[:-1], True]          # evaluate once per distinct score, so ties are handled together
    tp, fp = tp[last], fp[last]
    precision = tp / (tp + fp)
    recall = tp / total_pos
    return float(((recall - np.r_[0.0, recall[:-1]]) * precision).sum())


def threshold_at_fpr(y, s, target: float) -> float:
    """Smallest threshold t such that at most `target` of the benign URLs have score >= t."""
    neg = np.sort(np.asarray(s, dtype=float)[np.asarray(y) == 0])
    if len(neg) == 0:
        return float("nan")
    allowed = int(np.floor(target * len(neg)))      # false positives we can afford
    if allowed >= len(neg):
        return float(neg[0])
    # just above the (allowed+1)-th highest benign score => at most `allowed` benign URLs reach it
    return float(np.nextafter(neg[-(allowed + 1)], np.inf))


def rates_at(y, s, t: float) -> dict:
    y = np.asarray(y)
    flagged = np.asarray(s, dtype=float) >= t
    tp = int((flagged & (y == 1)).sum())
    fp = int((flagged & (y == 0)).sum())
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    return {"threshold": float(t), "fpr": fp / max(neg, 1), "recall": tp / max(pos, 1),
            "precision": tp / max(tp + fp, 1), "tp": tp, "fp": fp, "pos": pos, "neg": neg}


def recall_at_fpr(y, s, target: float) -> float:
    return rates_at(y, s, threshold_at_fpr(y, s, target))["recall"]


def bootstrap_ci(y, s, groups, fn, n_boot: int = 200, seed: int = 0, alpha: float = 0.05):
    """Resample whole groups (domains) with replacement and recompute fn(y, s). Returns (low, high)."""
    y = np.asarray(y)
    s = np.asarray(s, dtype=float)
    codes, uniq = pd.factorize(np.asarray(groups))
    rng = np.random.default_rng(seed)
    rows = np.arange(len(y))
    vals = []
    for _ in range(n_boot):
        pick = rng.integers(0, len(uniq), len(uniq))
        counts = np.bincount(pick, minlength=len(uniq))
        idx = np.repeat(rows, counts[codes])        # every URL repeated as often as its domain was drawn
        vals.append(fn(y[idx], s[idx]))
    lo, hi = np.nanpercentile(vals, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(lo), float(hi)


def brier(y, p) -> float:
    y = np.asarray(y, dtype=float)
    return float(np.mean((np.asarray(p, dtype=float) - y) ** 2))


def calibration_table(y, p, bins: int = 10) -> list[dict]:
    """Per probability bin: how many URLs, mean predicted probability, share that really are phishing."""
    y = np.asarray(y)
    p = np.asarray(p, dtype=float)
    edges = np.linspace(0, 1, bins + 1)
    which = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    out = []
    for b in range(bins):
        m = which == b
        if m.any():
            out.append({"bin": f"{edges[b]:.1f}-{edges[b + 1]:.1f}", "n": int(m.sum()),
                        "mean_predicted": float(p[m].mean()), "observed_phishing": float(y[m].mean())})
    return out
