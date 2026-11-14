"""
Own evaluation for the page-content model (step B). Written from scratch with numpy/pandas only; scikit-learn is
used elsewhere for the model, not for any number computed here.

Input: one row per test page with  label (1 = phishing), prob, group (cluster / domain id), source.

What it reports (all with a 95% confidence interval from a CLUSTER bootstrap, i.e. whole groups are resampled,
so near-identical pages of one phishing kit do not make the interval look tighter than it is):
    pr_auc              average precision (area under the precision-recall curve, step-wise)
    roc_auc             rank-based AUC (ties get average rank)
    recall@FPR 1%       share of phishing pages caught when at most 1% of benign pages may be flagged
    recall@FPR 0.5%     same at 0.5%
    brier, ece          calibration (how far prob is from the real frequency)
and the false-positive rate per benign source at the 1% operating point.

Recall at FPR 0.1% is NOT reported: it allows at most one false positive per 1000 benign test pages, which a few
thousand test pages cannot measure. `allowed_fp` in the result shows how many false positives the budget really is;
below 5 the number is marked `reliable: false`.

Command line (predictions saved by a training script as CSV with label,prob,group,source):
    python -m aidev.evaluation.eval_content_own --pred experiments/preds_x.csv --out experiments/eval_x.json
"""
from __future__ import annotations

import argparse
import json
import math

import numpy as np
import pandas as pd

MIN_ALLOWED_FP = 5          # a budget of fewer than 5 false positives is too coarse to trust


# --------------------------------------------------------------------------------------- metrics
def _arrays(y, p) -> tuple[np.ndarray, np.ndarray]:
    return np.asarray(y).astype(int), np.asarray(p, dtype=float)


def pr_auc(y, p) -> float:
    """Average precision: sum over operating points of (recall step) x precision. Tied scores form ONE point."""
    y, p = _arrays(y, p)
    n_pos = int(y.sum())
    if n_pos == 0 or n_pos == len(y):
        return math.nan
    order = np.argsort(-p, kind="mergesort")
    p_s, y_s = p[order], y[order]
    tp = np.cumsum(y_s)
    fp = np.cumsum(1 - y_s)
    last = np.r_[np.flatnonzero(np.diff(p_s) != 0), len(p_s) - 1]      # last row of every distinct score
    tp, fp = tp[last], fp[last]
    precision = tp / (tp + fp)
    recall = tp / n_pos
    return float(np.sum((recall - np.r_[0.0, recall[:-1]]) * precision))


def roc_auc(y, p) -> float:
    """P(random phishing page scores higher than random benign page), ties count half (Mann-Whitney U)."""
    y, p = _arrays(y, p)
    n_pos = int(y.sum())
    n_neg = len(y) - n_pos
    if n_pos == 0 or n_neg == 0:
        return math.nan
    ranks = pd.Series(p).rank(method="average").to_numpy()
    return float((ranks[y == 1].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg))


def recall_at_fpr(y, p, target_fpr: float) -> dict:
    """Highest recall with at most `target_fpr` of the benign pages flagged.

    Rule: flag a page when prob >= threshold. The threshold is the smallest value for which no more than
    floor(target_fpr * n_benign) benign pages are flagged."""
    y, p = _arrays(y, p)
    neg = np.sort(p[y == 0])[::-1]
    pos = p[y == 1]
    if len(neg) == 0 or len(pos) == 0:
        return {"recall": math.nan, "threshold": math.nan, "fpr": math.nan, "allowed_fp": 0, "reliable": False}
    k = int(math.floor(target_fpr * len(neg) + 1e-9))
    below = neg[k] if k < len(neg) else -math.inf                      # benign pages with prob > below: at most k
    threshold = float(np.nextafter(below, math.inf)) if k < len(neg) else 0.0
    return {"recall": float((pos >= threshold).mean()), "threshold": threshold,
            "fpr": float((neg >= threshold).mean()), "allowed_fp": k, "reliable": k >= MIN_ALLOWED_FP}


def brier(y, p) -> float:
    y, p = _arrays(y, p)
    return float(np.mean((p - y) ** 2))


def ece(y, p, bins: int = 10) -> float:
    """Expected calibration error with equal-width bins: weighted mean |frequency of phishing - mean prob|."""
    y, p = _arrays(y, p)
    idx = np.minimum((p * bins).astype(int), bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            total += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(total)


def at_threshold(y, p, threshold: float) -> dict:
    """Recall, false-positive rate, precision and accuracy when a page is flagged at prob >= threshold."""
    y, p = _arrays(y, p)
    flagged = p >= threshold
    pos = y == 1
    return {"threshold": float(threshold),
            "recall": float(flagged[pos].mean()) if pos.any() else math.nan,
            "fpr": float(flagged[~pos].mean()) if (~pos).any() else math.nan,
            "precision": float(y[flagged].mean()) if flagged.any() else math.nan,
            "accuracy": float((flagged == pos).mean())}


def fpr_by_source(df: pd.DataFrame, threshold: float) -> dict:
    """Per-source false-positive rate on benign pages and recall on phishing pages at `threshold`."""
    out = {}
    for s, g in df.groupby("source"):
        flagged = g.prob >= threshold
        d = {"n": int(len(g))}
        if (g.label == 0).any():
            d["fpr"] = float(flagged[g.label == 0].mean())
        if (g.label == 1).any():
            d["recall"] = float(flagged[g.label == 1].mean())
        out[s] = d
    return out


# ------------------------------------------------------------------------------------- bootstrap
def cluster_bootstrap(y, p, groups, metrics: dict, n_boot: int = 1000, seed: int = 42) -> dict:
    """95% CI (2.5 and 97.5 percentile) of every metric function f(y, p) -> float, resampling whole groups."""
    y, p = _arrays(y, p)
    codes, uniques = pd.factorize(pd.Series(groups))
    order = np.argsort(codes, kind="mergesort")
    cuts = np.cumsum(np.bincount(codes, minlength=len(uniques)))[:-1]
    members = np.split(order, cuts)
    rng = np.random.default_rng(seed)
    draws = {k: [] for k in metrics}
    skipped = 0
    for _ in range(n_boot):
        pick = rng.integers(0, len(members), len(members))
        idx = np.concatenate([members[i] for i in pick])
        yy, pp = y[idx], p[idx]
        if yy.min() == yy.max():                                       # resample lost a class: metric undefined
            skipped += 1
            continue
        for k, f in metrics.items():
            draws[k].append(f(yy, pp))
    ci = {}
    for k, v in draws.items():
        v = np.asarray(v, dtype=float)
        v = v[~np.isnan(v)]
        ci[k] = [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if len(v) else [math.nan, math.nan]
    ci["_n_groups"] = len(uniques)
    ci["_skipped_resamples"] = skipped
    return ci


# ---------------------------------------------------------------------------------------- driver
def evaluate(label, prob, group, source, fprs=(0.01, 0.005), n_boot: int = 1000, seed: int = 42,
             fixed_threshold: float | None = None) -> dict:
    """Full report for one set of test predictions.

    `recall@fpr...` pick the threshold ON the test set (the best the model could do). `fixed_threshold` is a threshold
    chosen earlier on separate validation data; the report then also gives the recall and false-positive rate that
    threshold really delivers on the test set (this is the honest number for a deployed model)."""
    df = pd.DataFrame({"label": np.asarray(label).astype(int), "prob": np.asarray(prob, float),
                       "group": np.asarray(group), "source": np.asarray(source)})
    y, p = df.label.to_numpy(), df.prob.to_numpy()
    metrics = {"pr_auc": pr_auc, "roc_auc": roc_auc, "brier": brier, "ece": ece}
    point = {k: f(y, p) for k, f in metrics.items()}
    ops = {}
    for t in fprs:
        name = f"recall@fpr{t * 100:g}%"
        r = recall_at_fpr(y, p, t)
        ops[name] = r
        point[name] = r["recall"]
        metrics[name] = (lambda yy, pp, _t=t: recall_at_fpr(yy, pp, _t)["recall"])
    if fixed_threshold is not None:
        for key in ("recall", "fpr", "precision", "accuracy"):
            point[f"fixed_{key}"] = at_threshold(y, p, fixed_threshold)[key]
            metrics[f"fixed_{key}"] = (lambda yy, pp, _k=key: at_threshold(yy, pp, fixed_threshold)[_k])
    ci = cluster_bootstrap(y, p, df.group, metrics, n_boot=n_boot, seed=seed)
    main_t = ops[f"recall@fpr{fprs[0] * 100:g}%"]["threshold"] if fixed_threshold is None else fixed_threshold
    notes = []
    for name, r in ops.items():
        if not r["reliable"]:
            notes.append(f"{name}: only {r['allowed_fp']} false positives allowed in this test set; treat as rough")
    return {"n_pages": int(len(df)), "n_phishing": int(y.sum()), "n_benign": int((1 - y).sum()),
            "n_groups": ci.pop("_n_groups"), "skipped_resamples": ci.pop("_skipped_resamples"),
            "point": point, "ci95": ci, "operating_points": ops, "fixed_threshold": fixed_threshold,
            "by_source_at_first_fpr": fpr_by_source(df, main_t), "notes": notes}


def format_report(res: dict) -> str:
    lines = [f"test pages {res['n_pages']} (phishing {res['n_phishing']}, benign {res['n_benign']}, "
             f"groups {res['n_groups']})", "metric                 value     95% CI (cluster bootstrap)"]
    for k, v in res["point"].items():
        lo, hi = res["ci95"].get(k, [math.nan, math.nan])
        lines.append(f"  {k:<20} {v:>7.4f}   [{lo:.4f}, {hi:.4f}]")
    for name, r in res["operating_points"].items():
        lines.append(f"  {name}: threshold {r['threshold']:.4f}, real FPR {r['fpr']:.4f}, allowed FP {r['allowed_fp']}")
    if res.get("fixed_threshold") is not None:
        lines.append(f"  (fixed_* rows: threshold {res['fixed_threshold']:.4f} chosen on validation data, not on this test set)")
    lines.append("per source at the " + ("fixed threshold:" if res.get("fixed_threshold") is not None else "first operating point:"))
    for s, d in res["by_source_at_first_fpr"].items():
        lines.append(f"  {s:<28} " + "  ".join(f"{k} {v:.3f}" if isinstance(v, float) else f"{k} {v}" for k, v in d.items()))
    lines += [f"NOTE: {n}" for n in res["notes"]]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pred", required=True, help="CSV with columns label,prob,group,source")
    ap.add_argument("--out", default="", help="write the report as JSON")
    ap.add_argument("--n-boot", type=int, default=1000)
    a = ap.parse_args()
    d = pd.read_csv(a.pred)
    r = evaluate(d.label, d.prob, d.group, d.source, n_boot=a.n_boot)
    print(format_report(r))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(r, f, indent=2)
