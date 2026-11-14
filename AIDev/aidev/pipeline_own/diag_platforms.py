"""
Where does model 1 win or lose?  Breaks the TEST results of a saved model down by hosting platform and by .my hosts.
Own code (pandas, numpy, joblib only). It does not change train_own.py or any model file.

    python -m aidev.pipeline_own.diag_platforms --model model_own_final3.joblib

It rebuilds the same split as train_own.py (same --data / --split / --seed / fractions), scores the test part with the
model that train_own saved with --save, uses the threshold stored in that file, and prints

  1. hosting platforms vs other hosts vs .my hosts:
     how many phishing / benign rows were in TRAIN, and phishing recall / benign false-positive rate on TEST
  2. the same for each hosting platform (largest first)
     -> shows whether the model learned "this platform = phishing" because the benign side of that platform is thin

Writes experiments/<model name>_platforms.json.
"""
from __future__ import annotations

import argparse
import json

import joblib
import numpy as np
import pandas as pd

from aidev.core.common import DATA, MODEL_PATH
from aidev.core.features import FEATURE_VERSION
from aidev.pipeline_own.build_dataset_own import PLATFORMS, _host, platform_of
from aidev.pipeline_own.train_own import load_xy, make_split, proba


def pct(x):
    return "   -  " if x is None else f"{100 * x:5.1f}%"


def rate(p, thr, mask):
    """(number of rows, share of them with score >= thr) for the rows where mask is True."""
    n = int(mask.sum())
    return n, (float((p[mask] >= thr).mean()) if n else None)


def main():
    ap = argparse.ArgumentParser(description="Break a saved model's test results down by hosting platform")
    ap.add_argument("--model", required=True, help="file name in models/, e.g. model_own_final3.joblib")
    ap.add_argument("--data", default="dataset_own.csv")
    ap.add_argument("--split", choices=("time", "domain"), default="time")
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--top", type=int, default=15, help="how many platforms to list")
    a = ap.parse_args()

    bundle = joblib.load(MODEL_PATH.with_name(a.model))
    if bundle.get("feature_version") != FEATURE_VERSION:
        raise SystemExit(f"{a.model} was trained with feature version {bundle.get('feature_version')}, "
                         f"the code now has {FEATURE_VERSION}. Retrain with train_own --save first.")
    model, thr = bundle["model"], float(bundle["threshold"])

    f = DATA / "service_domains.csv"                      # hosting platforms that build_dataset_own found automatically
    if f.exists():
        t = pd.read_csv(f, index_col=0)
        PLATFORMS.update(t.index[t["decision"].astype(str).str.startswith("hosting platform")])

    print(f"reading {a.data} and computing features (same steps as train_own) ...")
    df, X = load_xy(DATA / a.data)
    svc = (df["kind"] == "phish_on_service").to_numpy()   # train_own leaves these out too
    df, X = df[~svc].reset_index(drop=True), X[~svc]
    y = df["label"].to_numpy()
    split = make_split(df, a.split, a.test_frac, a.val_frac, a.seed)
    tr, te = np.flatnonzero(split == "train"), np.flatnonzero(split == "test")
    yt = y[te]
    p_te = proba(model, X[te])
    print(f"model {a.model}, threshold {thr:.3f}; train {len(tr)} rows, test {len(te)} rows "
          f"(test phishing {int((yt == 1).sum())}, benign {int((yt == 0).sum())})")

    hosts = [_host(u) for u in df["url"]]
    plat = np.array([platform_of(h) if h else "" for h in hosts], dtype=object)
    is_my = np.array([h.endswith(".my") for h in hosts])

    def row(name, mask):
        mtr, mte = mask[tr], mask[te]
        tr_pos, tr_neg = int(((y[tr] == 1) & mtr).sum()), int(((y[tr] == 0) & mtr).sum())
        n_pos, r_pos = rate(p_te, thr, mte & (yt == 1))
        n_neg, r_neg = rate(p_te, thr, mte & (yt == 0))
        print(f"  {name:22s} {tr_pos:>6d} / {tr_neg:<6d} | {n_pos:>6d} {pct(r_pos)} | {n_neg:>6d} {pct(r_neg)}")
        return {"name": name, "train_phishing": tr_pos, "train_benign": tr_neg, "test_phishing": n_pos,
                "recall": r_pos, "test_benign": n_neg, "false_positive_rate": r_neg}

    head = f"  {'':22s} {'TRAIN phish / benign':>20s} | {'TEST phishing':>13s} recall | {'TEST benign':>11s} FPR"
    print("\nhosting platforms vs other hosts (phishing: share caught; benign: share wrongly flagged)")
    print(head)
    groups = [row("hosting platforms", plat != ""), row("other hosts", plat == ""), row(".my hosts", is_my)]

    order = pd.Series(plat[plat != ""]).value_counts()
    print(f"\nper hosting platform (the {a.top} largest by number of rows)")
    print(head)
    per_platform = [row(name, plat == name) for name in order.head(a.top).index]

    out_dir = DATA.parent / "experiments"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"{a.model.replace('.joblib', '')}_platforms.json"
    out.write_text(json.dumps({"model": a.model, "threshold": thr, "groups": groups, "per_platform": per_platform},
                              indent=2), encoding="utf-8")
    print(f"\nwritten: experiments/{out.name}")


if __name__ == "__main__":
    main()
