"""
Page-content model, version 3 training and evaluation (steps C, E, F). Written from scratch; the only library
components used are scikit-learn's RandomForestClassifier and IsotonicRegression, plus pandas / numpy.

    python -m aidev.pipeline_own2.train_content2 --drop n_redirects,redirect_cross_domain,tls_invalid --out m2_v3 --ablate
    python -m aidev.pipeline_own2.train_content2 --drop n_redirects,redirect_cross_domain,tls_invalid --out m2_v3_own --test-on own

What it does, in order
  1. Reads data/pages/pages.csv + html, extracts the features and a structure fingerprint of every page.
  2. Groups pages into CAMPAIGNS (same fingerprint on different domains = one campaign) and splits BY CAMPAIGN
     into train / validation / test, so a phishing kit never has pages on both sides.
  3. Caps every campaign at --cap pages (default 20) in the training set only.
  4. Fits the Random Forest on train, fits isotonic calibration on validation, picks the decision threshold on
     validation so that at most 1% of benign validation pages are flagged.
  5. Evaluates on test (own evaluation module): PR-AUC, recall at fixed FPR, per-source FPR, 95% CI by campaign
     bootstrap, calibration, and the recall/FPR the validation threshold REALLY gives on test.
  6. --ablate: repeats 4-5 with each feature group removed (same split).
  7. Saves NAME.joblib / NAME.json / NAME_preds.csv / NAME_report.md under experiments/. --promote also copies the
     model to the live model_content.joblib (do this only for a model you accept).

Other options: --test-on own (test only on pages you crawled yourself), --no-dedup (split by domain only and no cap,
to SEE how much the old split flattered the score), --only-v2 (drop the six version-3 features), --no-size,
--cap N, --n-boot N, --pages-dir PATH, --seed N.

Speed: the first run reads all page files (minutes) and stores the features in data/pages/features_cache.joblib; later
runs reuse it (seconds) as long as pages.csv and the feature code are unchanged. --no-cache / --rebuild-cache override.

The saved model is fitted on train + test (everything except the validation part, which calibration and threshold
need unseen); the metrics printed come from the train-only fit. Say so in the report.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
from pathlib import Path
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression

from aidev.core.common import CONTENT_METRICS_PATH, CONTENT_MODEL_PATH, EXPERIMENTS, PAGES
from aidev.detection import content_features as cf
from aidev.evaluation import campaign_dedup as dedup
from aidev.evaluation import eval_content_own as ev

V3_FEATURES = ["brand_asset_hotlink", "brand_in_logo_alt", "brand_in_meta", "n_ext_domains", "login_form_no_own_links",
               "form_posts_to_ip_or_http"]
SIZE_FEATURES = ["n_links", "n_tags", "n_images", "log_text_len", "log_html_len", "n_words", "text_per_tag",
                 "n_scripts", "log_inline_script_len", "title_len"]
# Every feature in exactly one group (checked by tests/test_train_content2.py).
FEATURE_GROUPS = {
    "forms": ["n_forms", "has_password_field", "n_password_fields", "n_inputs", "n_hidden_inputs", "hidden_input_ratio",
              "form_external_action", "form_null_action", "form_script_or_mail_action", "has_submit", "has_email_field",
              "n_sensitive_inputs", "login_form_no_own_links", "form_posts_to_ip_or_http"],
    "brand_title": ["title_len", "title_empty", "title_matches_domain", "title_login_word", "brand_in_title_not_domain",
                    "brand_in_text_not_domain", "n_sensitive_words", "brand_asset_hotlink", "brand_in_logo_alt", "brand_in_meta"],
    "links_resources": ["n_links", "ext_link_ratio", "null_link_ratio", "n_images", "ext_image_ratio", "favicon_missing",
                        "favicon_external", "ext_resource_ratio", "n_download_links", "oauth_links", "n_ext_domains"],
    "scripts": ["n_scripts", "log_inline_script_len", "ext_script_ratio", "obfuscation_density", "rightclick_blocked",
                "n_iframes", "hidden_iframe", "meta_refresh", "js_redirect", "install_words"],
    "size_text": ["log_text_len", "n_words", "n_tags", "text_per_tag", "log_html_len", "thin_page", "has_copyright",
                  "has_lang_attr"],
    "redirects_tls": ["n_redirects", "redirect_cross_domain", "tls_invalid"],
}
FPR_TARGET = 0.01


# ----------------------------------------------------------------------------------------- data
def _extract_all(pages_dir) -> pd.DataFrame:
    """Read every page and extract features + fingerprint (slow: a few minutes for ~16,000 pages)."""
    meta = pd.read_csv(pages_dir / "pages.csv").drop_duplicates("url")
    rows = []
    total = len(meta)
    for i, r in enumerate(meta.itertuples(), 1):
        if i % 2000 == 0:
            print(f"  extracted {i}/{total} pages", flush=True)
        try:
            with gzip.open(pages_dir / "html" / r.html_file, "rt", encoding="utf-8", errors="replace") as f:
                html = f.read()
            redirects = [x for x in str(r.redirects).split("|") if x and x != "nan"]
            feats = cf.extract(html, r.final_url, redirects, bool(r.tls_invalid))
            fp = dedup.html_fingerprint(html, r.final_url)
        except Exception:
            continue
        rows.append({**feats, "label": int(r.label), "group": r.group, "source": r.source, "url": r.url, "fp": fp})
    return pd.DataFrame(rows)


def _cache_key(pages_dir) -> str:
    """Changes whenever pages.csv or the code that makes the features/fingerprints changes, so a stale cache is never used."""
    h = hashlib.sha1()
    st = (pages_dir / "pages.csv").stat()
    h.update(f"{st.st_size}:{st.st_mtime_ns}:{cf.CONTENT_FEATURE_VERSION}".encode())
    for mod in (cf, dedup):
        h.update(Path(mod.__file__).read_bytes())
    return h.hexdigest()


def load(pages_dir=PAGES, use_cache: bool = True, rebuild: bool = False) -> pd.DataFrame:
    """One row per page: features + label, group (domain), source, url, fp (fingerprint or None).

    The result is cached in data/pages/features_cache.joblib (data/ is not in git). The cache is used only when
    pages.csv, content_features.py and campaign_dedup.py are unchanged; otherwise it is rebuilt automatically."""
    cache = pages_dir / "features_cache.joblib"
    key = _cache_key(pages_dir)
    if use_cache and not rebuild and cache.exists():
        try:
            c = joblib.load(cache)
            if c.get("key") == key:
                print(f"using cached features ({cache.name}); --rebuild-cache to force a fresh read")
                return c["df"]
            print("cache is out of date (pages or feature code changed); rebuilding")
        except Exception:
            print("cache could not be read; rebuilding")
    df = _extract_all(pages_dir)
    if use_cache:
        try:
            joblib.dump({"key": key, "df": df}, cache)
        except Exception as exc:                          # a full disk must not stop the training
            print(f"could not write cache ({type(exc).__name__}); continuing without it")
    return df


def _rf(seed: int) -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
                                  random_state=seed, n_jobs=-1)


# ---------------------------------------------------------------------------------------- split
def split(df: pd.DataFrame, test_on: str = "", seed: int = 42, test_frac: float = 0.2, val_frac: float = 0.15):
    """Boolean masks (train, val, test) chosen by whole clusters. Needs df['cluster'] and df['source']."""
    rng = np.random.default_rng(seed)
    cl = df.cluster.to_numpy()
    if test_on == "own":
        own = ~df.source.str.startswith("phreshphish_")
        pool = np.unique(cl[own.to_numpy()])
        test_c = set(rng.choice(pool, size=max(1, int(round(0.3 * len(pool)))), replace=False))
        test = df.cluster.isin(test_c).to_numpy() & own.to_numpy()
        gone = df.cluster.isin(test_c).to_numpy()                       # every page of a test campaign leaves training
    else:
        pool = np.unique(cl)
        test_c = set(rng.choice(pool, size=max(1, int(round(test_frac * len(pool)))), replace=False))
        test = df.cluster.isin(test_c).to_numpy()
        gone = test
    rest = np.unique(cl[~gone])
    val_c = set(rng.choice(rest, size=max(1, int(round(val_frac * len(rest)))), replace=False))
    val = df.cluster.isin(val_c).to_numpy() & ~gone
    train = ~gone & ~val
    return train, val, test


# ------------------------------------------------------------------------------- fit + evaluate
def fit_calibrated(df: pd.DataFrame, names: list[str], train: np.ndarray, val: np.ndarray, cap: int, seed: int):
    """RF on (capped) train, isotonic calibration + threshold on val. Returns (model, calibrator, threshold, cap_report)."""
    tr = df[train]
    cap_report = {"cap": 0, "pages_before": int(len(tr)), "pages_kept": int(len(tr)), "pages_removed": 0, "clusters_capped": 0}
    if cap:
        keep, cap_report = dedup.cap_per_cluster(tr.cluster.to_numpy(), tr.label.to_numpy(), cap=cap, seed=seed)
        tr = tr[keep]
    model = _rf(seed).fit(tr[names], tr.label)
    v = df[val]
    if v.label.nunique() < 2:
        raise SystemExit("Validation part has only one class; cannot calibrate. Use more data or another --seed.")
    raw_v = model.predict_proba(v[names])[:, 1]
    cal = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(raw_v, v.label)
    op = ev.recall_at_fpr(v.label.to_numpy(), cal.predict(raw_v), FPR_TARGET)
    return model, cal, op["threshold"], cap_report, op


def evaluate_split(df, names, train, val, test, cap, seed, n_boot):
    model, cal, thr, cap_report, val_op = fit_calibrated(df, names, train, val, cap, seed)
    te = df[test]
    raw = model.predict_proba(te[names])[:, 1]
    calp = cal.predict(raw)
    args = (te.label.to_numpy(), None, te.cluster.to_numpy(), te.source.to_numpy())
    res_raw = ev.evaluate(args[0], raw, args[2], args[3], n_boot=n_boot, seed=seed)
    res_cal = ev.evaluate(args[0], calp, args[2], args[3], n_boot=n_boot, seed=seed, fixed_threshold=thr)
    return model, cal, thr, cap_report, val_op, raw, calp, res_raw, res_cal


def ablation(df, names, train, val, test, cap, seed, n_boot) -> list[dict]:
    """Retrain with each feature group removed (same split); report PR-AUC and recall@1% FPR on raw probabilities."""
    out = []
    metrics = {"pr_auc": ev.pr_auc, "recall@fpr1%": lambda y, p: ev.recall_at_fpr(y, p, FPR_TARGET)["recall"]}
    te = df[test]
    for group, members in [("(none, all features)", [])] + list(FEATURE_GROUPS.items()):
        use = [n for n in names if n not in members]
        if not use or (members and all(m not in names for m in members)):
            continue                                                    # nothing of this group is in the model
        tr = df[train]
        if cap:
            tr = tr[dedup.cap_per_cluster(tr.cluster.to_numpy(), tr.label.to_numpy(), cap=cap, seed=seed)[0]]
        p = _rf(seed).fit(tr[use], tr.label).predict_proba(te[use])[:, 1]
        y = te.label.to_numpy()
        ci = ev.cluster_bootstrap(y, p, te.cluster.to_numpy(), metrics, n_boot=n_boot, seed=seed)
        out.append({"removed": group, "n_features": len(use), "pr_auc": ev.pr_auc(y, p), "pr_auc_ci": ci["pr_auc"],
                    "recall_at_1pct_fpr": ev.recall_at_fpr(y, p, FPR_TARGET)["recall"], "recall_ci": ci["recall@fpr1%"]})
        print(f"  removed {group:<22} features {len(use):>2}  PR-AUC {out[-1]['pr_auc']:.4f}  recall@1%FPR {out[-1]['recall_at_1pct_fpr']:.4f}")
    return out


# ----------------------------------------------------------------------------------------- report
def markdown(name, mode, args, sizes, dedup_report, cap_report, res_raw, res_cal, thr, abl) -> str:
    def row(label, res, key):
        lo, hi = res["ci95"][key]
        return f"| {label} | {res['point'][key]:.4f} | [{lo:.4f}, {hi:.4f}] |"
    L = [f"# Content model results: {name}", "", f"- evaluation mode: {mode}", f"- command options: {args}",
         f"- pages: train {sizes['train']}, validation {sizes['val']}, test {sizes['test']} "
         f"(test phishing {res_raw['n_phishing']}, benign {res_raw['n_benign']}, campaigns {res_raw['n_groups']})",
         f"- campaigns: {dedup_report['n_clusters']} clusters from {dedup_report['n_domains']} domains; "
         f"{dedup_report['n_multi_domain_clusters']} span several domains ({dedup_report['domains_merged_away']} domains merged away); "
         f"largest cluster {dedup_report['largest_clusters_pages'][:3]} pages; mixed-label clusters {dedup_report.get('mixed_label_clusters', 'n/a')}",
         f"- training cap {cap_report['cap']}: {cap_report['pages_removed']} of {cap_report['pages_before']} training pages removed "
         f"in {cap_report['clusters_capped']} clusters", f"- decision threshold (calibrated probability, FPR <= 1% on validation): {thr:.4f}", "",
         "## Test results (95% CI: bootstrap over campaigns)", "", "| metric | value | 95% CI |", "|---|---|---|"]
    for k in ("pr_auc", "roc_auc", "recall@fpr1%", "recall@fpr0.5%"):
        L.append(row(k + " (raw probability)", res_raw, k))
    for k in ("brier", "ece"):
        L.append(row(k + " (raw)", res_raw, k))
        L.append(row(k + " (calibrated)", res_cal, k))
    for k in ("fixed_recall", "fixed_fpr", "fixed_precision"):
        L.append(row(f"{k} at validation threshold (calibrated)", res_cal, k))
    L += ["", "False-positive rate / recall per source at the validation threshold:", "", "| source | pages | FPR | recall |", "|---|---|---|---|"]
    for s, d in res_cal["by_source_at_first_fpr"].items():
        L.append(f"| {s} | {d['n']} | {d.get('fpr', float('nan')):.4f} | {d.get('recall', float('nan')):.4f} |")
    if res_raw["notes"]:
        L += ["", *[f"- NOTE: {n}" for n in res_raw["notes"]]]
    if abl:
        L += ["", "## Ablation by feature group (group removed, same split, raw probabilities)", "",
              "| removed group | features left | PR-AUC [95% CI] | recall @1% FPR [95% CI] |", "|---|---|---|---|"]
        for a in abl:
            L.append(f"| {a['removed']} | {a['n_features']} | {a['pr_auc']:.4f} [{a['pr_auc_ci'][0]:.4f}, {a['pr_auc_ci'][1]:.4f}] | "
                     f"{a['recall_at_1pct_fpr']:.4f} [{a['recall_ci'][0]:.4f}, {a['recall_ci'][1]:.4f}] |")
    return "\n".join(L) + "\n"


# ------------------------------------------------------------------------------------------ main
def main(pages_dir=PAGES, drop=None, test_on="", no_dedup=False, cap=20, n_boot=1000, seed=42, ablate=False,
         out="", promote=False, argv_text="", use_cache=True, rebuild_cache=False) -> dict:
    df = load(pages_dir, use_cache, rebuild_cache)
    names = [n for n in cf.FEATURE_NAMES if n not in (drop or [])]
    print(f"pages: {len(df)}  phishing {int(df.label.sum())}  benign {int((1 - df.label).sum())}  "
          f"domains {df.group.nunique()}  features used {len(names)}")
    if df.label.nunique() < 2 or len(df) < 200:
        raise SystemExit("Not enough pages. Run crawl_pages.py first.")
    if no_dedup:
        df["cluster"] = pd.factorize(df.group)[0]
        cap = 0
        dedup_report = {"n_pages": len(df), "n_domains": int(df.group.nunique()), "n_clusters": int(df.group.nunique()),
                        "n_multi_domain_clusters": 0, "domains_merged_away": 0, "largest_clusters_pages": [], "note": "dedup off"}
    else:
        df["cluster"], dedup_report = dedup.campaign_clusters(df.group, df.fp, df.label)
    print("campaigns:", json.dumps(dedup_report))
    train, val, test = split(df, test_on, seed)
    sizes = {"train": int(train.sum()), "val": int(val.sum()), "test": int(test.sum())}
    mode = ("own-pages-test" if test_on == "own" else "random-campaign-split") + ("-no-dedup" if no_dedup else "")
    print(f"split ({mode}): {sizes}")
    if df[test].label.nunique() < 2:
        raise SystemExit("Test set has only one class.")

    model, cal, thr, cap_report, val_op, raw, calp, res_raw, res_cal = evaluate_split(df, names, train, val, test, cap, seed, n_boot)
    print(f"\n== TEST, raw RF probability ==\n{ev.format_report(res_raw)}")
    print(f"\n== TEST, calibrated probability, threshold {thr:.4f} fixed on validation ==\n{ev.format_report(res_cal)}")
    print(f"training cap: {json.dumps(cap_report)}")
    imp = sorted(zip(names, model.feature_importances_), key=lambda x: -x[1])[:12]
    print("\nmost important features:")
    for n, v in imp:
        print(f"  {n:<28} {v:.3f}")

    abl = []
    if ablate:
        print("\n== ablation by feature group ==")
        abl = ablation(df, names, train, val, test, cap, seed, max(100, n_boot // 3))

    # saved model: everything except the validation part (calibration + threshold need unseen data)
    fit_rows = df[~val]
    if cap:
        fit_rows = fit_rows[dedup.cap_per_cluster(fit_rows.cluster.to_numpy(), fit_rows.label.to_numpy(), cap=cap, seed=seed)[0]]
    final = _rf(seed).fit(fit_rows[names], fit_rows.label)
    raw_v = final.predict_proba(df[val][names])[:, 1]
    cal_final = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip").fit(raw_v, df[val].label)
    thr_final = ev.recall_at_fpr(df[val].label.to_numpy(), cal_final.predict(raw_v), FPR_TARGET)["threshold"]
    version = "content-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    p = res_cal["point"]
    heldout = {"accuracy": p["fixed_accuracy"], "precision": p["fixed_precision"], "recall": p["fixed_recall"], "auc": p["roc_auc"]}
    bundle = {"model": final, "feature_names": names, "feature_version": cf.CONTENT_FEATURE_VERSION, "version": version,
              "metrics": heldout, "eval_mode": mode, "calibrator": cal_final, "threshold": float(thr_final)}
    if out:
        EXPERIMENTS.mkdir(exist_ok=True)
        joblib.dump(bundle, EXPERIMENTS / f"{out}.joblib")
        te = df[test]
        pd.DataFrame({"label": te.label.to_numpy(), "prob": raw, "prob_cal": calp, "group": te.cluster.to_numpy(),
                      "source": te.source.to_numpy(), "url": te.url.to_numpy()}).to_csv(EXPERIMENTS / f"{out}_preds.csv", index=False)
        report = {"version": version, "eval_mode": mode, "sizes": sizes, "campaigns": dedup_report, "cap": cap_report,
                  "threshold_eval_fit": thr, "threshold_saved_model": float(thr_final), "test_raw": res_raw,
                  "test_calibrated": res_cal, "top_features": imp, "ablation": abl, "features_used": names,
                  "dropped": sorted(set(drop or [])), "options": argv_text}
        (EXPERIMENTS / f"{out}.json").write_text(json.dumps(report, indent=2, default=float), encoding="utf-8")
        (EXPERIMENTS / f"{out}_report.md").write_text(markdown(out, mode, argv_text, sizes, dedup_report, cap_report, res_raw,
                                                               res_cal, thr, abl), encoding="utf-8")
        print(f"\nsaved experiments/{out}.joblib, .json, _preds.csv, _report.md  [{mode}]")
        if promote:
            shutil.copyfile(EXPERIMENTS / f"{out}.joblib", CONTENT_MODEL_PATH)
            shutil.copyfile(EXPERIMENTS / f"{out}.json", CONTENT_METRICS_PATH)
            print(f"PROMOTED to the live model ({CONTENT_MODEL_PATH.name})")
    elif promote:
        raise SystemExit("--promote needs --out NAME")
    return report if out else {"test_raw": res_raw, "test_calibrated": res_cal}


if __name__ == "__main__":
    import sys
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--drop", default="", help="comma-separated feature names to leave out")
    ap.add_argument("--no-size", action="store_true")
    ap.add_argument("--only-v2", action="store_true", help="leave out the six version-3 features")
    ap.add_argument("--test-on", default="", choices=["", "own"])
    ap.add_argument("--no-dedup", action="store_true", help="split by domain only, no campaign grouping, no cap")
    ap.add_argument("--cap", type=int, default=20, help="max training pages per campaign (0 = no cap)")
    ap.add_argument("--n-boot", type=int, default=1000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--ablate", action="store_true")
    ap.add_argument("--out", default="", help="save under experiments/NAME.*")
    ap.add_argument("--promote", action="store_true", help="also copy the saved model to the live model_content.joblib")
    ap.add_argument("--pages-dir", default="")
    ap.add_argument("--no-cache", action="store_true", help="always re-read all pages, do not use or write the feature cache")
    ap.add_argument("--rebuild-cache", action="store_true", help="re-read all pages and overwrite the feature cache")
    a = ap.parse_args()
    drop = [x for x in a.drop.split(",") if x]
    if a.no_size:
        drop += [x for x in SIZE_FEATURES if x not in drop]
    if a.only_v2:
        drop += [x for x in V3_FEATURES if x not in drop]
    kw = {}
    if a.pages_dir:
        kw["pages_dir"] = Path(a.pages_dir)
    main(drop=drop, test_on=a.test_on, no_dedup=a.no_dedup, cap=a.cap, n_boot=a.n_boot, seed=a.seed, ablate=a.ablate,
         out=a.out, promote=a.promote, argv_text=" ".join(sys.argv[1:]),
         use_cache=not a.no_cache, rebuild_cache=a.rebuild_cache, **kw)
