"""
Train the Random Forest.   python train.py

Writes model.joblib (model + feature names + version + metrics) and model_metrics.json.
Splits by registered domain (GroupShuffleSplit) so the test set contains only domains
the model never saw, and prints the false-positive rate, which the thesis cares about.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import GroupShuffleSplit
from urllib.parse import urlsplit

from common import DATA, METRICS_PATH, MODEL_PATH
from features import FEATURE_NAMES, FEATURE_VERSION, normalise, vector

VERSION = "v1.0.0"
SEED = 42


def _fpr(y, pred) -> float:
    neg = (y == 0)
    return float(((pred == 1) & neg).sum() / max(neg.sum(), 1))


def main() -> None:
    df = pd.read_csv(DATA / "dataset.csv")
    X, keep = [], []
    for i, u in enumerate(df["url"]):
        try:
            X.append(vector(u)); keep.append(i)
        except Exception:
            pass
    df = df.iloc[keep].reset_index(drop=True)
    X = np.array(X, dtype=float)
    y = df["label"].to_numpy()
    groups = df["group"].to_numpy()

    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, y, groups))
    rf = RandomForestClassifier(
        n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
        n_jobs=-1, random_state=SEED,
    )
    rf.fit(X[tr], y[tr])

    proba = rf.predict_proba(X[te])[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "version": VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rows_total": int(len(df)),
        "rows_train": int(len(tr)),
        "rows_test": int(len(te)),
        "domains_test": int(len(set(groups[te]))),
        "split": "GroupShuffleSplit by registered domain, test_size=0.2",
        "threshold": 0.5,
        "accuracy": float(accuracy_score(y[te], pred)),
        "precision": float(precision_score(y[te], pred, zero_division=0)),
        "recall": float(recall_score(y[te], pred, zero_division=0)),
        "f1": float(f1_score(y[te], pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y[te], proba)),
        "false_positive_rate": _fpr(y[te], pred),
        "fpr_at_0.7": _fpr(y[te], (proba >= 0.7).astype(int)),
        "threshold_table": {
            f"{t:.1f}": {"false_positive_rate": round(_fpr(y[te], (proba >= t).astype(int)), 4),
                         "recall": round(float(recall_score(y[te], (proba >= t).astype(int), zero_division=0)), 4)}
            for t in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)},
        "feature_importance": dict(sorted(
            zip(FEATURE_NAMES, map(float, rf.feature_importances_)), key=lambda kv: -kv[1])),
    }

    # Diagnostic: is the model leaning on the path? Re-score the same test URLs reduced to
    # "scheme://host/". A big drop in AUC means it learned path artefacts, not host patterns.
    def _root(u: str) -> str:
        p = urlsplit(normalise(u))
        return f"{p.scheme}://{p.netloc}/"
    Xr = np.array([vector(_root(u)) for u in df["url"].iloc[te]], dtype=float)
    pr = rf.predict_proba(Xr)[:, 1]
    metrics["root_only"] = {
        "roc_auc": float(roc_auc_score(y[te], pr)),
        "false_positive_rate": _fpr(y[te], (pr >= 0.5).astype(int)),
        "recall": float(recall_score(y[te], (pr >= 0.5).astype(int), zero_division=0)),
    }

    joblib.dump({"model": rf, "feature_names": FEATURE_NAMES, "feature_version": FEATURE_VERSION, "version": VERSION,
                 "metrics": metrics}, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Saved {MODEL_PATH.name}")
    for k in ("accuracy", "precision", "recall", "f1", "roc_auc", "false_positive_rate", "fpr_at_0.7"):
        print(f"  {k:20s} {metrics[k]:.4f}")
    print("  threshold  false_pos  recall")
    for t, v in metrics["threshold_table"].items():
        print(f"    {t:>5}     {v['false_positive_rate']:.4f}    {v['recall']:.4f}")
    ro = metrics["root_only"]
    print(f"  root-only check (paths removed): auc {ro['roc_auc']:.4f}  false_pos {ro['false_positive_rate']:.4f}  recall {ro['recall']:.4f}")
    print("  top features:", ", ".join(list(metrics["feature_importance"])[:5]))


if __name__ == "__main__":
    main()
