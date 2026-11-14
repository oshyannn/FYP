"""
Error analysis (step H): which pages does the content model get wrong, and why? Own rules, pandas/numpy only.

    python -m aidev.evaluation.error_analysis --pred experiments/m2_v3_own_preds.csv --out experiments/m2_v3_own_errors.md

Uses the test predictions saved by train_content2 (NAME_preds.csv) and the feature cache. The decision point is the
raw-probability threshold at 1% false-positive rate (same as the report), or --threshold X.
  * every false positive / false negative gets ONE cause from the rules below, counted over ALL errors;
  * --n random examples of each kind are listed (random, not the worst, so the list is representative).
Safety: phishing URLs are written defanged (hxxp, [.]); never open them in a normal browser. URLs from the source
`benign_history` (your own browsing history) are hidden.
"""
from __future__ import annotations

import argparse

import joblib
import numpy as np
import pandas as pd

from aidev.core import common
from aidev.core.common import PAGES
from aidev.evaluation import eval_content_own as ev


def defang(url: str) -> str:
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def cause_fn(f: dict, on_shared_host: bool) -> str:
    """Why was this PHISHING page missed? First matching rule wins."""
    if on_shared_host:
        return "on a shared hosting / link-shortener platform (the saved page may be the platform's own)"
    if f.get("thin_page", 0) or f.get("n_words", 0) < 30:
        return "tiny page: almost no text to judge"
    if f.get("meta_refresh", 0) or f.get("js_redirect", 0):
        return "redirector page (meta refresh or JavaScript redirect)"
    if f.get("n_forms", 0) == 0:
        return "no form at all (landing / lure page)"
    if f.get("has_password_field", 0) or f.get("n_sensitive_inputs", 0) > 0:
        return "has a credential form but no other strong signal"
    return "has a form, nothing sensitive"


def cause_fp(f: dict) -> str:
    """Why was this BENIGN page flagged? First matching rule wins."""
    if f.get("has_password_field", 0) or f.get("n_sensitive_inputs", 0) > 0:
        return "real login / payment form"
    if f.get("brand_in_title_not_domain", 0) or f.get("brand_in_logo_alt", 0) or f.get("brand_in_meta", 0):
        return "mentions another brand (partner, single sign-on, app badge)"
    if f.get("thin_page", 0) or f.get("n_words", 0) < 30:
        return "tiny page: almost no text to judge"
    if f.get("ext_link_ratio", 0) > 0.6 or f.get("ext_resource_ratio", 0) > 0.6:
        return "mostly links / resources on other websites"
    return "no obvious cause (ordinary page)"


def _shared(group, shared: set[str]) -> bool:
    g = str(group if group is not None else "").lower()
    return any(g == s or g.endswith("." + s) for s in shared)


def analyse(pred: pd.DataFrame, feats: pd.DataFrame, threshold: float | None = None, n: int = 30, seed: int = 42,
            shared: set[str] | None = None) -> dict:
    """Join predictions with features by url, find the errors, give each a cause."""
    shared = shared or set()
    f = feats.drop_duplicates("url").set_index("url")
    d = pred.copy()
    d = d[d.url.isin(f.index)].reset_index(drop=True)
    if threshold is None:
        threshold = ev.recall_at_fpr(d.label.to_numpy(), d.prob.to_numpy(), 0.01)["threshold"]
    fp = d[(d.label == 0) & (d.prob >= threshold)]
    fn = d[(d.label == 1) & (d.prob < threshold)]
    # the predictions file only has numeric campaign ids in `group`; the domain comes from the feature table
    rows = lambda x, fn_: [fn_(f.loc[u].to_dict(), f.loc[u].get("group", "")) for u in x.url]
    fn_c = pd.Series(rows(fn, lambda ft, g: cause_fn(ft, _shared(g, shared))), index=fn.index, dtype=object)
    fp_c = pd.Series(rows(fp, lambda ft, g: cause_fp(ft)), index=fp.index, dtype=object)
    return {"threshold": float(threshold), "n_pages": int(len(d)), "n_fp": int(len(fp)), "n_fn": int(len(fn)),
            "n_benign": int((d.label == 0).sum()), "n_phishing": int((d.label == 1).sum()),
            "fn_causes": fn_c.value_counts().to_dict(), "fp_causes": fp_c.value_counts().to_dict(),
            "fn_sources": fn.source.value_counts().to_dict(), "fp_sources": fp.source.value_counts().to_dict(),
            "fn_sample": _sample(fn, fn_c, f, n, seed, True), "fp_sample": _sample(fp, fp_c, f, n, seed, False)}


def _sample(errs: pd.DataFrame, causes: pd.Series, f: pd.DataFrame, n: int, seed: int, is_phish: bool) -> list[dict]:
    pick = errs.sample(min(n, len(errs)), random_state=seed) if len(errs) else errs
    out = []
    for i, r in pick.iterrows():
        ft = f.loc[r.url]
        url = "(hidden: browsing history)" if r.source == "benign_history" else (defang(r.url) if is_phish else r.url)
        out.append({"source": r.source, "prob": round(float(r.prob), 3), "url": url, "cause": causes[i],
                    "n_words": int(ft.get("n_words", 0)), "n_forms": int(ft.get("n_forms", 0)),
                    "password": int(ft.get("has_password_field", 0)), "ext_link_ratio": round(float(ft.get("ext_link_ratio", 0)), 2)})
    return out


def to_markdown(res: dict, title: str = "") -> str:
    L = [f"# Error analysis {title}", "",
         f"- threshold (raw probability, 1% false-positive rate on this test set): {res['threshold']:.4f}",
         f"- test pages {res['n_pages']}: phishing {res['n_phishing']}, benign {res['n_benign']}",
         f"- missed phishing pages (false negatives): {res['n_fn']} ({res['n_fn'] / max(res['n_phishing'], 1):.1%})",
         f"- wrongly flagged benign pages (false positives): {res['n_fp']} ({res['n_fp'] / max(res['n_benign'], 1):.1%})", "",
         "## Why phishing pages were missed (all of them)", "", "| cause | pages | share |", "|---|---|---|"]
    L += [f"| {k} | {v} | {v / max(res['n_fn'], 1):.1%} |" for k, v in res["fn_causes"].items()]
    L += ["", "False negatives by source: " + ", ".join(f"{k} {v}" for k, v in res["fn_sources"].items()), "",
          "## Why benign pages were flagged (all of them)", "", "| cause | pages | share |", "|---|---|---|"]
    L += [f"| {k} | {v} | {v / max(res['n_fp'], 1):.1%} |" for k, v in res["fp_causes"].items()]
    L += ["", "False positives by source: " + ", ".join(f"{k} {v}" for k, v in res["fp_sources"].items()), ""]
    for name, key in (("Random sample of missed phishing pages (URLs defanged: do NOT open)", "fn_sample"),
                      ("Random sample of wrongly flagged benign pages", "fp_sample")):
        L += [f"## {name}", "", "| source | prob | url | cause | words | forms | password | ext link ratio |", "|---|---|---|---|---|---|---|---|"]
        L += [f"| {r['source']} | {r['prob']} | `{r['url']}` | {r['cause']} | {r['n_words']} | {r['n_forms']} | {r['password']} | {r['ext_link_ratio']} |"
              for r in res[key]]
        L.append("")
    return "\n".join(L)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pred", required=True, help="experiments/NAME_preds.csv from train_content2")
    ap.add_argument("--cache", default=str(PAGES / "features_cache.joblib"))
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    pred = pd.read_csv(a.pred)
    feats = joblib.load(a.cache)["df"]
    shared = set(common.lines(common.LISTS / "shared_hosts.txt"))
    res = analyse(pred, feats, a.threshold, a.n, shared=shared)
    md = to_markdown(res, a.pred)
    print(md)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(md)
