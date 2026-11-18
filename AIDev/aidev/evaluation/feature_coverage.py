"""
How often does each feature fire, per class and per source? (own analysis, pandas only)

    python -m aidev.evaluation.feature_coverage                 # the six version-3 features
    python -m aidev.evaluation.feature_coverage --all --out experiments/feature_coverage.csv

Reads the feature cache written by train_content2 (data/pages/features_cache.joblib). A feature that is almost never
non-zero cannot help a model much; this explains a null result in the ablation or in the v2-vs-v3 comparison.
"Fires" = value > 0. Columns: share of phishing pages, share of benign pages, and the share per source.
"""
from __future__ import annotations

import argparse

import joblib
import pandas as pd

from aidev.core.common import PAGES

V3 = ["brand_asset_hotlink", "brand_in_logo_alt", "brand_in_meta", "n_ext_domains", "login_form_no_own_links",
      "form_posts_to_ip_or_http"]
META = {"label", "group", "source", "url", "fp", "cluster"}


def coverage(df: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    """One row per feature: n, share firing among phishing / benign pages and per source."""
    rows = []
    for f in features:
        fires = df[f] > 0
        row = {"feature": f, "phishing": float(fires[df.label == 1].mean()), "benign": float(fires[df.label == 0].mean())}
        for s, g in df.groupby("source"):
            row[s] = float(fires[g.index].mean())
        rows.append(row)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cache", default=str(PAGES / "features_cache.joblib"))
    ap.add_argument("--all", action="store_true", help="all features, not only the six version-3 ones")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    d = joblib.load(a.cache)["df"].reset_index(drop=True)
    feats = [c for c in d.columns if c not in META] if a.all else [f for f in V3 if f in d.columns]
    t = coverage(d, feats)
    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 20)
    print(f"pages {len(d)} (phishing {int(d.label.sum())}); share of pages where the feature is > 0")
    print(t.round(3).to_string(index=False))
    if a.out:
        t.to_csv(a.out, index=False)
