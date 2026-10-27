"""
Import a public labelled URL dataset (CSV) as extra training data.

    python -m aidev.pipeline.import_labeled dataset.csv --url-col URL --label-col label --benign-value 1

Writes data/benign_labeled.csv and data/phishing_labeled.csv (build_dataset.py reads them).
Check the dataset's documentation for which label value means "legitimate" and pass it as
--benign-value; everything else is treated as phishing. Verify licence terms before use.
Example candidate: PhiUSIIL Phishing URL Dataset (UCI #967).
"""
from __future__ import annotations

import argparse

import pandas as pd

from aidev.core.common import DATA


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--url-col", default="URL")
    ap.add_argument("--label-col", default="label")
    ap.add_argument("--benign-value", required=True, help="label value meaning legitimate, e.g. 1 or benign")
    a = ap.parse_args()

    df = pd.read_csv(a.csv, usecols=[a.url_col, a.label_col]).dropna()
    df[a.label_col] = df[a.label_col].astype(str).str.strip().str.lower()
    benign = df[a.label_col] == a.benign_value.strip().lower()
    DATA.mkdir(exist_ok=True)
    pd.DataFrame({"url": df.loc[benign, a.url_col]}).drop_duplicates().to_csv(DATA / "benign_labeled.csv", index=False)
    pd.DataFrame({"url": df.loc[~benign, a.url_col]}).drop_duplicates().to_csv(DATA / "phishing_labeled.csv", index=False)
    print(f"benign_labeled.csv: {int(benign.sum())}   phishing_labeled.csv: {int((~benign).sum())}")
    print("Sanity check: open both files and confirm the benign one really contains normal sites.")


if __name__ == "__main__":
    main()
