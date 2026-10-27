"""
Train the page-content Random Forest from data/pages (made by crawl_pages.py and import_phreshphish.py).

    python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid
    python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid --no-size --out exp_nosize
    python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid --test-on own --out exp_own

Options:
  --drop a,b,c      leave out chosen features
  --no-size         also leave out the page-size features (links, tags, text length, scripts...), the "cheating check"
  --time-split      train on older pages, test on the newest. NOTE: with PhreshPhish (2024-25) + your own crawl (2026)
                    this is really a cross-source test, not a pure time test
  --test-on own     test ONLY on pages you crawled yourself (source not starting with "phreshphish_"), because that
                    is what predict_content.py sees online (static fetch by pagefetch.py). Own pages are split by
                    domain (30% of own domains -> test); everything else is used for training.
  --no-own-train    with --test-on own: train on PhreshPhish only (pure cross-source test)
  --out NAME        save model/metrics as NAME.joblib / NAME.json instead of overwriting the live model_content.*
                    ALWAYS use this for experiments.

Evaluation is split BY REGISTERED DOMAIN (a domain is never in both train and test), with a threshold table showing
the false-positive rate per benign source and the most important features.
"""
from __future__ import annotations

import argparse
import gzip
import json
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from aidev.detection import content_features as cf
from aidev.core.common import CONTENT_METRICS_PATH, CONTENT_MODEL_PATH, EXPERIMENTS, PAGES

SIZE_FEATURES = ["n_links", "n_tags", "n_images", "log_text_len", "log_html_len", "n_words", "text_per_tag",
                 "n_scripts", "log_inline_script_len", "title_len"]


def load(pages_dir=PAGES) -> pd.DataFrame:
    meta = pd.read_csv(pages_dir / "pages.csv").drop_duplicates("url")
    rows = []
    for r in meta.itertuples():
        try:
            with gzip.open(pages_dir / "html" / r.html_file, "rt", encoding="utf-8", errors="replace") as f:
                html = f.read()
            redirects = [x for x in str(r.redirects).split("|") if x and x != "nan"]
            feats = cf.extract(html, r.final_url, redirects, bool(r.tls_invalid))
        except Exception:
            continue
        rows.append({**feats, "label": int(r.label), "group": r.group, "source": r.source, "url": r.url,
                     "fetched_at": str(r.fetched_at)})
    return pd.DataFrame(rows)


def _rf() -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
                                  random_state=42, n_jobs=-1)


def main(pages_dir=PAGES, drop: list[str] | None = None, time_split: bool = False, test_on: str = "",
         no_own_train: bool = False, out_model=CONTENT_MODEL_PATH, out_metrics=CONTENT_METRICS_PATH) -> dict:
    df = load(pages_dir)
    names = [n for n in cf.FEATURE_NAMES if n not in (drop or [])]
    print(f"pages: {len(df)}  phishing {int(df.label.sum())}  benign {int((1 - df.label).sum())}  domains {df.group.nunique()}")
    print(f"features used: {len(names)}")
    if df.label.nunique() < 2 or len(df) < 200:
        raise SystemExit("Not enough pages. Run crawl_pages.py first.")

    mode = "random-domain-split"
    if test_on == "own":
        mode = "own-pages-test" + ("-phresh-only-train" if no_own_train else "")
        df = df.reset_index(drop=True)
        own_mask = ~df.source.str.startswith("phreshphish_")
        own_pos = np.flatnonzero(own_mask.to_numpy())
        if len(own_pos) < 200:
            raise SystemExit("Too few self-crawled pages for --test-on own. Run crawl_pages.py first.")
        own = df.iloc[own_pos]
        if own.label.nunique() < 2:
            raise SystemExit("Self-crawled pages contain only one class.")
        _, o_te = next(GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42).split(own, own.label, own.group))
        te = own_pos[o_te]
        test_groups = set(df.group.iloc[te])
        in_test_group = df.group.isin(test_groups).to_numpy()
        keep = ~in_test_group
        if no_own_train:
            keep &= ~own_mask.to_numpy()
        tr = np.flatnonzero(keep)
        print(f"test on own pages: train {len(tr)} pages, test {len(te)} pages "
              f"(phishing {int(df.label.iloc[te].sum())}, benign {int((1 - df.label.iloc[te]).sum())})"
              + ("  [trained on PhreshPhish only]" if no_own_train else ""))
    elif time_split:
        mode = "time-split"
        df = df[df.fetched_at.str.len() > 3].sort_values("fetched_at").reset_index(drop=True)
        cut = int(len(df) * 0.8)
        train_groups = set(df.group[:cut])
        te = [i for i in range(cut, len(df)) if df.group[i] not in train_groups]
        tr = list(range(cut))
        print(f"time split: train up to {df.fetched_at[cut - 1][:10]}, test {df.fetched_at[cut][:10]} onwards ({len(te)} pages)")
        print("  (if the test sources below contain no 'phreshphish_*', this is a cross-source test, not a pure time test)")
    else:
        tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42).split(df, df.label, df.group))

    X_tr, y_tr, X_te, y_te = df.iloc[tr][names], df.iloc[tr].label, df.iloc[te][names], df.iloc[te].label
    if y_te.nunique() < 2:
        raise SystemExit("Test set has only one class; cannot compute AUC.")
    clf = _rf().fit(X_tr, y_tr)
    prob = clf.predict_proba(X_te)[:, 1]
    pred = prob >= 0.5
    m = {"accuracy": accuracy_score(y_te, pred), "precision": precision_score(y_te, pred, zero_division=0),
         "recall": recall_score(y_te, pred), "auc": roc_auc_score(y_te, prob)}
    print(f"held-out ({mode}):  " + "  ".join(f"{k} {v:.4f}" for k, v in m.items()))

    test = df.iloc[te].assign(prob=prob)
    ben = test[test.label == 0]
    srcs = sorted(ben.source.unique())
    print("\nthreshold   recall(phishing caught)   false-positive rate   " + "   ".join(srcs))
    table = []
    for t in (0.3, 0.5, 0.7, 0.8, 0.9, 0.95):
        rec = float((test[test.label == 1].prob >= t).mean())
        fpr = float((ben.prob >= t).mean())
        per = {s: float((g.prob >= t).mean()) for s, g in ben.groupby("source")}
        table.append({"threshold": t, "recall": rec, "fpr": fpr, "fpr_by_source": per})
        print(f"  {t:<8}  {rec:>10.1%}                 {fpr:>8.1%}            " + "   ".join(f"{per[s]:.1%}" for s in srcs))
    print(f"  (test benign per source: " + ", ".join(f"{s}={int((ben.source == s).sum())}" for s in srcs) + ")")

    imp = sorted(zip(names, clf.feature_importances_), key=lambda x: -x[1])[:12]
    print("\nmost important features (should be phishing signals, not page size):")
    for n, v in imp:
        print(f"  {n:<28} {v:.3f}")

    final = _rf().fit(df[names], df.label)
    version = "content-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    joblib.dump({"model": final, "feature_names": names, "feature_version": cf.CONTENT_FEATURE_VERSION,
                 "version": version, "metrics": m, "eval_mode": mode}, out_model)
    out_metrics.write_text(json.dumps({"version": version, "eval_mode": mode, "heldout": m, "thresholds": table,
                                       "top_features": imp, "n_pages": len(df), "dropped": sorted(set(drop or []))},
                                      indent=2), encoding="utf-8")
    print(f"\nsaved {out_model.name} ({version})  [{mode}]")
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--drop", default="", help="comma-separated feature names to leave out")
    ap.add_argument("--no-size", action="store_true", help="also leave out the page-size features")
    ap.add_argument("--time-split", action="store_true", help="test on the newest pages instead of random domains")
    ap.add_argument("--test-on", default="", choices=["", "own"], help="'own' = test only on pages you crawled yourself")
    ap.add_argument("--no-own-train", action="store_true", help="with --test-on own: do not train on your own pages")
    ap.add_argument("--out", default="", help="save as NAME.joblib / NAME.json instead of overwriting the live model")
    a = ap.parse_args()
    drop = [x for x in a.drop.split(",") if x]
    if a.no_size:
        drop += [x for x in SIZE_FEATURES if x not in drop]
    kw = {}
    if a.out:
        EXPERIMENTS.mkdir(exist_ok=True)
        kw = {"out_model": EXPERIMENTS / f"{a.out}.joblib", "out_metrics": EXPERIMENTS / f"{a.out}.json"}
    main(drop=drop, time_split=a.time_split, test_on=a.test_on, no_own_train=a.no_own_train, **kw)
