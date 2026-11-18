"""
Check same_owner() on REAL high-similarity benign pairs, then score it against your own labels.

Step 1 (writes a CSV you label by hand):
    python -m aidev.evaluation.check_same_owner --pred experiments/m2_v3_own_preds.csv --out experiments/same_owner_check.csv

  Open the CSV, fill the column human_label with  same  or  different  (leave blank if you cannot tell).

Step 2 (score the rule against your labels):
    python -m aidev.evaluation.check_same_owner --score experiments/same_owner_check.csv

Prints domains and evidence only, never full URLs (benign_history is never shown). Pages are only read, never opened.
"""
from __future__ import annotations

import argparse

import pandas as pd

from aidev.core.common import PAGES
from aidev.evaluation import clone_diagnostic as cd
from aidev.evaluation.platform_domains import url_domain
from aidev.evaluation.same_owner import same_owner


def build_pairs(pred_csv: str, pages_csv: str, min_sim: float, n_refs: int, seed: int) -> pd.DataFrame:
    pred = pd.read_csv(pred_csv)
    pages = pd.read_csv(pages_csv).drop_duplicates("url")
    pages = pages.assign(domain=pages.url.map(url_domain))
    res = cd.run(pred_csv, pages_csv, n_refs, 600, seed, None)
    bg = res["scored"]["benign (background)"]
    hits = bg[bg.sim >= min_sim].copy()

    html_of_url = dict(zip(pages.url, pages.html_file))
    refs = pages[(pages.label == 0) & pages.source.isin(cd.REF_SOURCES)]
    html_of_domain = {}
    for dom, hf in zip(refs.domain, refs.html_file):
        html_of_domain.setdefault(dom, hf)

    seen, rows = set(), []
    for r in hits.itertuples():
        if r.source == "benign_history":
            continue
        a = url_domain(r.url)
        b = r.copies
        if not a or not b or a == b:
            continue
        key = tuple(sorted((a, b)))
        if key in seen:
            continue
        seen.add(key)
        ha = cd.read_html(html_of_url.get(r.url))
        hb = cd.read_html(html_of_domain.get(b))
        if ha is None or hb is None:
            continue
        res_so = same_owner(a, ha, b, hb)
        rows.append({"domain_a": a, "domain_b": b, "sim": round(float(r.sim), 3),
                     "verdict": res_so["verdict"], "evidence": " | ".join(res_so["evidence"]),
                     "human_label": ""})
    return pd.DataFrame(rows)


def score(csv_path: str) -> None:
    df = pd.read_csv(csv_path, keep_default_na=False)
    lab = df[df.human_label.str.strip().str.lower().isin(["same", "different"])].copy()
    lab["human"] = lab.human_label.str.strip().str.lower()
    print(f"labelled pairs: {len(lab)} of {len(df)} (unlabelled rows are ignored)")
    if not len(lab):
        print("Fill the human_label column first.")
        return
    print(lab.groupby(["verdict", "human"]).size().to_string())
    said_same = lab[lab.verdict == "same"]
    if len(said_same):
        ok = (said_same.human == "same").mean()
        print(f"\nrule said 'same': {len(said_same)} pairs, really same: {ok:.1%}")
    unk = lab[lab.verdict == "unknown"]
    if len(unk):
        print(f"rule said 'unknown': {len(unk)} pairs, of which really same: {(unk.human == 'same').sum()}")
    wrong = lab[((lab.verdict == "same") & (lab.human == "different"))]
    if len(wrong):
        print("\nwrong 'same' verdicts (domains and evidence):")
        print(wrong[["domain_a", "domain_b", "evidence"]].to_string(index=False))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pred", default="")
    ap.add_argument("--pages", default=str(PAGES / "pages.csv"))
    ap.add_argument("--min-sim", type=float, default=0.5, help="only check pairs at least this similar")
    ap.add_argument("--refs", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="experiments/same_owner_check.csv")
    ap.add_argument("--score", default="", help="CSV with human_label filled in")
    a = ap.parse_args()
    if a.score:
        score(a.score)
    else:
        if not a.pred:
            ap.error("--pred is required unless --score is used")
        df = build_pairs(a.pred, a.pages, a.min_sim, a.refs, a.seed)
        df.to_csv(a.out, index=False)
        print(df[["domain_a", "domain_b", "sim", "verdict"]].to_string(index=False))
        print(f"\n{len(df)} pairs written to {a.out}. Fill human_label, then run with --score {a.out}")
