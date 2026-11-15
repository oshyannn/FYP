"""
Is there a '.my means safe' shortcut?  TLD-swap probe WITH controls (own code).

    python -m aidev.pipeline_own.probe_tld --model model_own_final_stack.joblib

Takes the TEST phishing URLs (same split as train_final_own.py), swaps only the ending of the host and scores them again with
the saved model:   x.y.xyz  ->  x.y.com / x.y.com.sg / x.y.com.au / x.y.com.my
Every swap removes the signal of the ORIGINAL ending (.xyz, .top ... are risky on their own), so a drop after the swap to
.com.my does not by itself prove a .my shortcut. What counts is the difference between .com.my and the controls
(.com.sg, .com.au: same shape, another country). A second table uses only URLs that already end in .com, where the swap to
.com.my changes almost nothing but the country.
Needs a model saved by train_final_own.py. Writes experiments/<model name>_tld_probe.json.
"""
from __future__ import annotations

import argparse
import json
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd

from aidev.core.common import DATA, MODEL_PATH
from aidev.core.features import FEATURE_VERSION, normalise, vector
from aidev.core.urltext import ngram_score
from aidev.pipeline_own.build_dataset_own import PLATFORMS, _host, platform_of
from aidev.pipeline_own.train_own import load_xy, make_split, proba

TARGETS = (".com", ".com.sg", ".com.au", ".com.my")


def swap(url, suffix):
    """Replace the last label of the host with `suffix` (e.g. '.com.my'). None for IPs or when nothing would change."""
    u = normalise(url).lower()
    host = urlsplit(u).hostname or ""
    labels = host.split(".")
    if len(labels) < 2 or all(p.isdigit() for p in labels) or host.endswith(suffix):
        return None
    return u.replace(host, ".".join(labels[:-1]) + suffix, 1)


def main():
    ap = argparse.ArgumentParser(description="TLD-swap probe with controls")
    ap.add_argument("--model", required=True, help="file name in models/, e.g. model_own_final_stack.joblib")
    ap.add_argument("--data", default="dataset_own.csv")
    ap.add_argument("--split", choices=("time", "domain"), default="time")
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    bundle = joblib.load(MODEL_PATH.with_name(a.model))
    if bundle.get("feature_version") != FEATURE_VERSION or bundle.get("ngram") is None:
        raise SystemExit("this probe needs a stacked model saved by train_final_own.py with the current feature version")
    model, thr, ng = bundle["model"], float(bundle["threshold"]), bundle["ngram"]

    f = DATA / "service_domains.csv"
    if f.exists():
        t = pd.read_csv(f, index_col=0)
        PLATFORMS.update(t.index[t["decision"].astype(str).str.startswith("hosting platform")])

    print(f"reading {a.data} and computing features (same steps as train_final_own) ...")
    df, X = load_xy(DATA / a.data)
    svc = (df["kind"] == "phish_on_service").to_numpy()
    df = df[~svc].reset_index(drop=True)
    y = df["label"].to_numpy()
    split = make_split(df, a.split, a.test_frac, a.val_frac, a.seed)
    te = np.flatnonzero(split == "test")
    urls = df["url"].to_numpy()[te]
    hosts = [_host(u) for u in urls]
    on_platform = np.array([bool(platform_of(h)) if h else False for h in hosts])
    is_my = np.array([h.endswith(".my") for h in hosts])
    phish = urls[(y[te] == 1) & ~on_platform & ~is_my]
    print(f"model {a.model}, threshold {thr:.4f}; test phishing URLs on ordinary hosts: {len(phish)}")

    def score(url_list):
        rows, ngs, ok = [], [], []
        for i, u in enumerate(url_list):
            try:
                rows.append(vector(u))
                ngs.append(ngram_score(ng, u))
                ok.append(i)
            except Exception:
                pass
        return np.array(ok), proba(model, np.c_[np.array(rows, dtype=float), np.array(ngs)])

    def table(title, base_urls):
        if len(base_urls) == 0:
            print(f"\n{title}: no URLs in the test set")
            return {}
        base_ok, base_p = score(list(base_urls))
        results = {"original": {"n": int(len(base_ok)), "flagged": float((base_p >= thr).mean()),
                                "mean_raw_probability": float(base_p.mean())}}
        print(f"\n{title}  (n={len(base_ok)}; share flagged at the threshold / mean raw probability)")
        print(f"  {'original ending':22s} {100 * results['original']['flagged']:5.1f}%   {results['original']['mean_raw_probability']:.3f}")
        for suf in TARGETS:
            pairs = [(i, swap(base_urls[i], suf)) for i in base_ok]
            pairs = [(i, v) for i, v in pairs if v]
            if not pairs:
                continue
            ok, p = score([v for _, v in pairs])
            # compare with the same URLs before the swap
            idx_before = {i: k for k, i in enumerate(base_ok)}
            before = np.array([base_p[idx_before[pairs[j][0]]] for j in ok])
            results[suf] = {"n": int(len(ok)), "flagged": float((p >= thr).mean()), "flagged_before_same_urls": float((before >= thr).mean()),
                            "mean_raw_probability": float(p.mean())}
            print(f"  -> {suf:19s} {100 * results[suf]['flagged']:5.1f}%   {results[suf]['mean_raw_probability']:.3f}"
                  f"   (same URLs before the swap: {100 * results[suf]['flagged_before_same_urls']:.1f}%)")
        return results

    out = {"model": a.model, "threshold": thr,
           "all_ordinary_phishing": table("all test phishing on ordinary hosts", phish),
           "originally_dot_com": table("only URLs that already end in .com",
                                       np.array([u for u in phish if (urlsplit(normalise(u).lower()).hostname or "").endswith(".com")]))}
    print("\nHow to read it: the .com.my row against .com.sg / .com.au. About the same = no .my-specific shortcut "
          "(the drop is just the lost signal of the original ending). Clearly lower = the model treats .my as safe.")
    out_dir = DATA.parent / "experiments"
    out_dir.mkdir(exist_ok=True)
    p = out_dir / f"{a.model.replace('.joblib', '')}_tld_probe.json"
    p.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"written: experiments/{p.name}")


if __name__ == "__main__":
    main()
