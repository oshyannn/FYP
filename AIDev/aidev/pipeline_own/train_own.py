"""
Own training + evaluation for AI model 1 (URL model).  Only pandas, numpy and scikit-learn's generic
classes are used; the splitting, metrics, threshold choice and reports are written here.

    python -m aidev.pipeline_own.train_own --split time   --out time_rf
    python -m aidev.pipeline_own.train_own --split domain --out domain_rf
    python -m aidev.pipeline_own.train_own --split time   --out time_hgb --model hgb
    python -m aidev.pipeline_own.train_own --split time   --out time_rf --ablate
    python -m aidev.pipeline_own.train_own --split time   --out final --save    # also writes models/model_own_final.joblib
    python -m aidev.pipeline_own.train_own --split time   --out ng --ngram       # does a character n-gram model help?

Splits (65% train / 15% validation / 20% test; no domain is ever in two parts)
  domain   random split by group (same idea as the old train.py, so the numbers can be compared)
  time     phishing URLs that have a date: oldest 65% train, next 15% validation, NEWEST 20% test.
           Phishing without a date stays in train. Benign URLs are split by domain at random.
           This asks "does the model catch phishing that appeared AFTER the training data?".
The threshold is chosen on the validation part (flag at most --fpr of benign URLs), then measured on test.
Probabilities are calibrated with isotonic regression fitted on the validation part.
Results: AIDev/experiments/<out>.json and <out>_errors.csv (the 100 worst false positives / misses).
Nothing here touches models/model.joblib, so the running app is unchanged.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.isotonic import IsotonicRegression

from aidev.core.common import DATA, MODEL_PATH
from aidev.core.features import FEATURE_NAMES, FEATURE_VERSION, normalise, vector
from aidev.pipeline_own import metrics_own as M

FEATURE_GROUPS = {
    "host_shape": ["host_length", "num_dots_host", "num_hyphens_host", "num_digits_host", "digit_ratio_host",
                   "num_subdomains", "host_is_ip", "longest_host_label", "reg_label_length", "tld_length",
                   "num_host_tokens", "avg_token_length"],
    "host_randomness": ["host_entropy", "max_consonant_run", "vowel_ratio_host", "digit_letter_switches", "has_punycode"],
    "host_risk": ["risky_tld", "brand_mismatch", "has_at_symbol"],
    "path": ["path_length", "num_path_segments", "num_suspicious_words", "path_special_chars", "path_has_risky_ext",
             "path_pct_encoded", "path_digit_ratio", "longest_path_token", "path_double_slash"],
}
FPR_TARGETS = (0.05, 0.02, 0.01, 0.005)

def is_realistic(source):
    """Benign rows from real sites: crawled pages, CrUX top sites, own history."""
    s = pd.Series(np.asarray(source).astype(str))
    return (s.str.startswith("pages_") | s.str.startswith("benign_crux") | (s == "own_history")).to_numpy()


# ------------------------------------------------------------------ data
def load_xy(path):
    df = pd.read_csv(path)
    for c, default in (("source", "unknown"), ("kind", "unknown"), ("hard_negative", 0), ("synthetic_path", 0)):
        if c not in df:
            df[c] = default
    if "first_seen" not in df:
        df["first_seen"] = None
    rows, keep = [], []
    for i, u in enumerate(df["url"]):
        try:
            rows.append(vector(u))
            keep.append(i)
        except Exception:
            pass
        if (i + 1) % 50000 == 0:
            print(f"  features {i + 1}/{len(df)}")
    df = df.iloc[keep].reset_index(drop=True)
    return df, np.array(rows, dtype=float)


def make_split(df, mode, test_frac, val_frac, seed):
    rng = np.random.default_rng(seed)
    groups = df["group"].astype(str).to_numpy()
    y = df["label"].to_numpy()
    split = np.full(len(df), "train", dtype=object)
    if mode == "domain":
        perm = rng.permutation(np.unique(groups))
        nt, nv = int(len(perm) * test_frac), int(len(perm) * val_frac)
        split[np.isin(groups, perm[:nt])] = "test"
        split[np.isin(groups, perm[nt:nt + nv])] = "val"
    else:
        fs = pd.to_datetime(df["first_seen"], utc=True, errors="coerce")
        idx = np.flatnonzero((y == 1) & fs.notna().to_numpy())
        if len(idx) < 200:
            raise SystemExit(f"time split needs dated phishing URLs, found {len(idx)}. "
                             "Run import_phishtank_dated, then build_dataset_own again.")
        idx = idx[np.argsort(fs.to_numpy()[idx], kind="stable")]
        nt, nv = int(len(idx) * test_frac), int(len(idx) * val_frac)
        split[idx[len(idx) - nt:]] = "test"
        split[idx[len(idx) - nt - nv:len(idx) - nt]] = "val"
        perm = rng.permutation(np.unique(groups[y == 0]))
        bt, bv = int(len(perm) * test_frac), int(len(perm) * val_frac)
        split[(y == 0) & np.isin(groups, perm[:bt])] = "test"
        split[(y == 0) & np.isin(groups, perm[bt:bt + bv])] = "val"
    # a domain that is in test must not appear in val/train; one in val must not appear in train
    test_g = set(groups[split == "test"])
    val_g = set(groups[split == "val"]) - test_g
    split[np.isin(groups, list(test_g)) & (split != "test")] = "drop"
    split[np.isin(groups, list(val_g)) & (split == "train")] = "drop"
    return split


# ------------------------------------------------------------------ model
def fit_model(kind, X, y, trees, seed):
    if kind == "rf":
        m = RandomForestClassifier(n_estimators=trees, min_samples_leaf=2, class_weight="balanced_subsample",
                                   n_jobs=-1, random_state=seed)
        return m.fit(X, y)
    w = np.where(y == 1, 0.5 * len(y) / max((y == 1).sum(), 1), 0.5 * len(y) / max((y == 0).sum(), 1))
    m = HistGradientBoostingClassifier(max_iter=trees, learning_rate=0.08, max_leaf_nodes=63, random_state=seed)
    return m.fit(X, y, sample_weight=w)


def proba(model, X):
    return model.predict_proba(X)[:, list(model.classes_).index(1)]


# ------------------------------------------------------------------ reporting helpers
def flagged_rates(df, s, thr, col):
    out = []
    for val, sub in df.groupby(col, dropna=False):
        for lab in (1, 0):
            m = sub["label"].to_numpy() == lab
            if m.any():
                out.append({"value": str(val), "label": lab, "n": int(m.sum()),
                            "flagged": float((s[sub.index.to_numpy()[m]] >= thr).mean())})
    return out


def benign_category(df):
    hn, syn = df["hard_negative"].to_numpy(), df["synthetic_path"].to_numpy()
    return np.where((hn == 1) & (syn == 0), "real_hard_negative",
                    np.where((hn == 1) & (syn == 1), "synthetic_id_or_my_path", "other_benign"))


def ngram_text(u, host_only=False):
    p = urlsplit(normalise(u))
    h = (p.hostname or "")
    h = h[4:] if h.startswith("www.") else h
    return (h if host_only else h + (p.path or "")).lower()


def pct(x):
    return f"{100 * x:.1f}%"


def run(args):
    path = DATA / args.data
    print(f"reading {path.name} and computing features ...")
    df, X = load_xy(path)
    svc = (df["kind"] == "phish_on_service").to_numpy() & (not args.keep_service)
    df_svc, X_svc = df[svc].reset_index(drop=True), X[svc]
    if svc.any():
        print(f"leaving out {int(svc.sum())} phishing rows on URL shorteners / QR services / big sites "
              "(the URL text cannot show them; they are scored separately below)")
    df, X = df[~svc].reset_index(drop=True), X[~svc]
    y = df["label"].to_numpy()
    split = make_split(df, args.split, args.test_frac, args.val_frac, args.seed)
    tr, va, te = (np.flatnonzero(split == k) for k in ("train", "val", "test"))
    print(f"split={args.split}: train {len(tr)}, val {len(va)}, test {len(te)}, dropped {int((split == 'drop').sum())}")
    for name, ix in (("train", tr), ("val", va), ("test", te)):
        print(f"  {name:5s} phishing {int((y[ix] == 1).sum()):>6d}  benign {int((y[ix] == 0).sum()):>6d}")

    info = {"rows": {k: int(len(ix)) for k, ix in (("train", tr), ("val", va), ("test", te))},
            "phishing": {k: int((y[ix] == 1).sum()) for k, ix in (("train", tr), ("val", va), ("test", te))},
            "benign": {k: int((y[ix] == 0).sum()) for k, ix in (("train", tr), ("val", va), ("test", te))}}
    if args.split == "time":
        fs = pd.to_datetime(df["first_seen"], utc=True, errors="coerce")
        for k, ix in (("train", tr), ("val", va), ("test", te)):
            d = fs.iloc[ix][y[ix] == 1].dropna()
            if len(d):
                info[f"{k}_phishing_dates"] = [d.min().strftime("%Y-%m-%d"), d.max().strftime("%Y-%m-%d")]
        print("  dated phishing, train:", info.get("train_phishing_dates"), " test:", info.get("test_phishing_dates"))

    print(f"training {args.model} ({args.trees} trees/iterations) ...")
    model = fit_model(args.model, X[tr], y[tr], args.trees, args.seed)
    p_val, p_te = proba(model, X[va]), proba(model, X[te])
    yv, yt = y[va], y[te]

    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p_val, yv)
    pc_te = iso.predict(p_te)
    src_va = df["source"].astype(str).to_numpy()[va]
    realistic_va = (yv == 0) & is_realistic(src_va)
    use_real = args.fpr_pool == "realistic" and int(realistic_va.sum()) >= 300
    if args.fpr_pool == "realistic" and not use_real:
        print(f"warning: only {int(realistic_va.sum())} realistic benign validation rows; the threshold uses ALL benign rows")
    pool = ((yv == 1) | realistic_va) if use_real else np.ones(len(yv), dtype=bool)
    thr = M.threshold_at_fpr(yv[pool], p_val[pool], args.fpr)
    print(f"threshold {thr:.3f} for FPR <= {100 * args.fpr:g}% on "
          + (f"{int(realistic_va.sum())} realistic benign validation URLs (crawled sites + own history)" if use_real
             else "all benign validation URLs"))
    gt = df["group"].astype(str).to_numpy()[te]
    dte = df.iloc[te].reset_index(drop=True)

    res = {"config": {**vars(args), "feature_version": FEATURE_VERSION, "data_rows": int(len(df)),
                      "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}, "split_info": info}
    res["test"] = {
        "roc_auc": M.roc_auc(yt, p_te), "pr_auc": M.average_precision(yt, p_te),
        "pr_auc_ci95": M.bootstrap_ci(yt, p_te, gt, M.average_precision, args.boot, args.seed),
        "recall_at_fpr": {f"{100 * t:g}%": M.recall_at_fpr(yt, p_te, t) for t in FPR_TARGETS},
        "recall_at_1pct_fpr_ci95": M.bootstrap_ci(yt, p_te, gt, lambda a, b: M.recall_at_fpr(a, b, 0.01), args.boot, args.seed),
        "operating_point": {"chosen_on_validation_for_fpr": args.fpr, **M.rates_at(yt, p_te, thr)},
        "old_thresholds": {"0.5": M.rates_at(yt, p_te, 0.5), "0.7": M.rates_at(yt, p_te, 0.7)},
        "brier_raw": M.brier(yt, p_te), "brier_calibrated": M.brier(yt, pc_te),
        "calibration_table": M.calibration_table(yt, pc_te),
    }
    src_te = dte["source"].astype(str).to_numpy()
    real_te = (yt == 0) & is_realistic(src_te)
    phi_te = (yt == 0) & (src_te == "phiusiil_benign")
    res["test"]["threshold_pool"] = "realistic benign (pages_* + own_history)" if use_real else "all benign"
    res["test"]["fpr_crawled_real_benign"] = {"n": int(real_te.sum()), "fpr": float((p_te[real_te] >= thr).mean()) if real_te.any() else None}
    res["test"]["fpr_phiusiil_benign"] = {"n": int(phi_te.sum()), "fpr": float((p_te[phi_te] >= thr).mean()) if phi_te.any() else None}
    keep_pl = (yt == 1) | real_te                      # all phishing + only the realistic benign URLs
    ypl, spl, gpl = yt[keep_pl], p_te[keep_pl], gt[keep_pl]
    res["test_realistic_pool"] = {
        "benign_n": int(real_te.sum()), "positive_n": int((yt == 1).sum()), "roc_auc": M.roc_auc(ypl, spl),
        "recall_at_fpr": {f"{100 * x:g}%": M.recall_at_fpr(ypl, spl, x) for x in FPR_TARGETS},
        "recall_at_1pct_fpr_ci95": M.bootstrap_ci(ypl, spl, gpl, lambda a, b: M.recall_at_fpr(a, b, 0.01), args.boot, args.seed),
        "note": "benign side = crawled real sites + own history only; PhiUSIIL homepages and synthetic paths are left out",
    }

    def real_recall(s_, target=0.01):
        return M.recall_at_fpr(yt[keep_pl], s_[keep_pl], target)

    cat = benign_category(dte)
    res["breakdown"] = {"source": flagged_rates(dte, p_te, thr, "source"), "kind": flagged_rates(dte, p_te, thr, "kind"),
                        "benign_category": [{"value": c, "n": int((cat == c).sum()),
                                             "flagged": float((p_te[(cat == c) & (yt == 0)] >= thr).mean())}
                                            for c in np.unique(cat[yt == 0])]}

    if len(df_svc):
        ps = proba(model, X_svc)
        res["phish_on_service"] = {"n": int(len(df_svc)), "flagged_at_threshold": float((ps >= thr).mean()),
                                   "top_domains": df_svc["group"].value_counts().head(10).to_dict()}

    # root-only check: re-score the test URLs reduced to "scheme://host/"
    def _root(u):
        p = urlsplit(normalise(u))
        return f"{p.scheme}://{p.netloc}/"
    pr = proba(model, np.array([vector(_root(u)) for u in dte["url"]], dtype=float))
    res["test"]["root_only"] = {"roc_auc": M.roc_auc(yt, pr), "recall_at_1pct_fpr": M.recall_at_fpr(yt, pr, 0.01)}

    if args.ablate:
        print("ablation (retraining without one feature group at a time) ...")
        abl = []
        base = {"pr_auc": res["test"]["pr_auc"], "recall_at_1pct_fpr": res["test"]["recall_at_fpr"]["1%"],
                "recall_at_1pct_fpr_realistic": res["test_realistic_pool"]["recall_at_fpr"]["1%"]}
        for gname, cols in FEATURE_GROUPS.items():
            keep = [i for i, n in enumerate(FEATURE_NAMES) if n not in cols]
            m2 = fit_model(args.model, X[tr][:, keep], y[tr], args.ablate_trees, args.seed)
            s2 = proba(m2, X[te][:, keep])
            abl.append({"removed": gname, "n_features_left": len(keep), "pr_auc": M.average_precision(yt, s2),
                        "recall_at_1pct_fpr": M.recall_at_fpr(yt, s2, 0.01), "recall_at_1pct_fpr_realistic": real_recall(s2)})
        res["ablation"] = {"full_model_for_comparison": base, "rows": abl,
                           "note": f"ablation models use {args.ablate_trees} trees, so compare rows with each other and with a "
                                   f"{args.ablate_trees}-tree full model, not exactly with the main run"}

    if args.ngram:
        from sklearn.feature_extraction.text import HashingVectorizer
        from sklearn.linear_model import SGDClassifier
        from sklearn.model_selection import GroupKFold
        print("n-gram experiment: character 3-5-grams of host + path, hashed, logistic regression ...")
        hv = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2 ** 20, alternate_sign=False, norm="l2")
        H = hv.transform([ngram_text(u, args.ngram_host_only) for u in df["url"]]).tocsr()

        def _lin():
            return SGDClassifier(loss="log_loss", alpha=2e-6, max_iter=15, tol=None, class_weight="balanced", random_state=args.seed)
        Htr, ytr, gtr = H[tr], y[tr], df["group"].astype(str).to_numpy()[tr]
        oof = np.zeros(len(tr))
        for a_i, b_i in GroupKFold(n_splits=5).split(Htr, ytr, gtr):
            oof[b_i] = _lin().fit(Htr[a_i], ytr[a_i]).predict_proba(Htr[b_i])[:, 1]
        lin = _lin().fit(Htr, ytr)
        ng_te = lin.predict_proba(H[te])[:, 1]
        stack = fit_model(args.model, np.c_[X[tr], oof], ytr, args.trees, args.seed)
        st_te = proba(stack, np.c_[X[te], ng_te])

        def _row(name, s_):
            lo_, hi_ = M.bootstrap_ci(yt[keep_pl], s_[keep_pl], gpl,
                                      lambda a, b: M.recall_at_fpr(a, b, 0.01), args.boot, args.seed)
            return {"name": name, "roc_auc": M.roc_auc(yt, s_), "recall_1pct_all_benign": M.recall_at_fpr(yt, s_, 0.01),
                    "recall_1pct_realistic_benign": real_recall(s_), "realistic_ci95": [lo_, hi_]}
        res["ngram_experiment"] = [_row("feature model alone", p_te), _row("character n-gram model alone", ng_te),
                                   _row("average of the two", (p_te + ng_te) / 2),
                                   _row("feature model + n-gram score as an extra feature", st_te)]

    # errors worth reading by hand (own browsing history is left out of the file)
    ed = dte.assign(score=p_te)
    fp = ed[(ed.label == 0) & (ed.source != "own_history")].sort_values("score", ascending=False).head(100).assign(error="false_positive")
    fn = ed[ed.label == 1].sort_values("score").head(100).assign(error="missed_phishing")
    out_dir = DATA.parent / "experiments"
    out_dir.mkdir(exist_ok=True)
    pd.concat([fp, fn])[["error", "score", "url", "source", "kind", "first_seen", "group"]].to_csv(
        out_dir / f"{args.out}_errors.csv", index=False)
    (out_dir / f"{args.out}.json").write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")

    if args.save:
        imp = (dict(sorted(zip(FEATURE_NAMES, map(float, model.feature_importances_)), key=lambda kv: -kv[1]))
               if hasattr(model, "feature_importances_") else {})
        metrics = {"test": res["test"], "split": args.split, "feature_importance": imp, "split_info": info}
        out_model = MODEL_PATH.with_name(f"model_own_{args.out}.joblib")
        joblib.dump({"model": model, "calibrator": iso, "threshold": float(thr),
                     "threshold_calibrated": float(iso.predict([thr])[0]), "threshold_fpr_target": args.fpr,
                     "feature_names": FEATURE_NAMES, "feature_version": FEATURE_VERSION,
                     "version": f"own-{args.out}", "metrics": metrics}, out_model)
        print(f"saved {out_model.name} (not used by the app until you copy it over model.joblib)")
    report(res, args)
    print(f"\nfull results: experiments/{args.out}.json   errors to read: experiments/{args.out}_errors.csv")


def report(res, args):
    t = res["test"]
    lo, hi = t["pr_auc_ci95"]
    print(f"\n=== {args.split} split | {args.model} | test set ===")
    print(f"ROC-AUC {t['roc_auc']:.3f}   PR-AUC {t['pr_auc']:.3f}  (95% interval {lo:.3f} to {hi:.3f})")
    r = t["recall_at_fpr"]
    print("phishing caught if at most this share of benign URLs may be flagged:  " +
          "   ".join(f"{k} -> {pct(v)}" for k, v in r.items()))
    rl, rh = t["recall_at_1pct_fpr_ci95"]
    print(f"  (1% case, 95% interval {pct(rl)} to {pct(rh)})")
    op = t["operating_point"]
    rp = res["test_realistic_pool"]
    rlo, rhi = rp["recall_at_1pct_fpr_ci95"]
    print(f"HEADLINE (benign side = {rp['benign_n']} crawled real sites + own history only): phishing caught at "
          + "   ".join(f"{k} FPR -> {pct(v)}" for k, v in rp["recall_at_fpr"].items()) + f"   (1%: 95% interval {pct(rlo)} to {pct(rhi)})")
    print("  the row above counts all benign URLs, 94% of which are easy PhiUSIIL homepages, so it looks better than real life")
    print(f"operating point: threshold {op['threshold']:.3f} chosen on validation for FPR <= {pct(args.fpr)} -> "
          f"test FPR {pct(op['fpr'])}, recall {pct(op['recall'])}, precision {pct(op['precision'])}")
    fr, fp_ = t["fpr_crawled_real_benign"], t["fpr_phiusiil_benign"]
    if fr["fpr"] is not None and fp_["fpr"] is not None:
        print(f"false-positive rate at that threshold: PhiUSIIL benign {pct(fp_['fpr'])} (n={fp_['n']}) | "
              f"crawled real benign sites {pct(fr['fpr'])} (n={fr['n']})  <- the second is closer to real life")
    for k, v in t["old_thresholds"].items():
        print(f"  at the old threshold {k}: FPR {pct(v['fpr'])}, recall {pct(v['recall'])}")
    print(f"probabilities: Brier raw {t['brier_raw']:.4f} -> calibrated {t['brier_calibrated']:.4f} (lower is better; "
          "calibrated to THIS dataset's phishing share, not real traffic)")
    print(f"root-only check: ROC-AUC {t['root_only']['roc_auc']:.3f}, recall at 1% FPR {pct(t['root_only']['recall_at_1pct_fpr'])}")
    print("\nflagged share by source (phishing = recall, benign = false-positive rate):")
    for row in res["breakdown"]["source"]:
        print(f"  {'phishing' if row['label'] == 1 else 'benign  '} {row['value']:24s} n={row['n']:<6d} {pct(row['flagged'])}")
    if "phish_on_service" in res:
        ps = res["phish_on_service"]
        print(f"phishing on shorteners / QR / big sites (not in training or the numbers above): n={ps['n']}, "
              f"flagged {pct(ps['flagged_at_threshold'])}  <- a URL-only model cannot be expected to catch these")
    print("benign by category (false-positive rate):")
    for row in res["breakdown"]["benign_category"]:
        print(f"  {row['value']:26s} n={row['n']:<6d} {pct(row['flagged'])}")
    if "ngram_experiment" in res:
        print("\nn-gram experiment (recall at 1% FPR, all benign | realistic benign):")
        for r in res["ngram_experiment"]:
            ci = r.get("realistic_ci95")
            print(f"  {r['name']:52s} ROC-AUC {r['roc_auc']:.3f} | {pct(r['recall_1pct_all_benign'])} | {pct(r['recall_1pct_realistic_benign'])}"
                  + (f"  (95%: {pct(ci[0])} to {pct(ci[1])})" if ci else ""))
    if "ablation" in res:
        a = res["ablation"]
        b = a["full_model_for_comparison"]
        print("\nablation (without this group):  PR-AUC | recall at 1% FPR (all benign) | recall at 1% FPR (realistic benign)")
        print(f"  {'(all features)':22s} {b['pr_auc']:.3f} | {pct(b['recall_at_1pct_fpr'])} | {pct(b['recall_at_1pct_fpr_realistic'])}   [main run]")
        for row in a["rows"]:
            print(f"  {row['removed']:22s} {row['pr_auc']:.3f} | {pct(row['recall_at_1pct_fpr'])} | {pct(row['recall_at_1pct_fpr_realistic'])}")


def main():
    ap = argparse.ArgumentParser(description="Own training + evaluation for model 1")
    ap.add_argument("--data", default="dataset_own.csv")
    ap.add_argument("--split", choices=("time", "domain"), default="time")
    ap.add_argument("--model", choices=("rf", "hgb"), default="rf")
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--fpr", type=float, default=0.01, help="false-positive budget for the threshold (default 1%%)")
    ap.add_argument("--fpr-pool", choices=("realistic", "all"), default="realistic",
                    help="which benign validation URLs set the threshold (default: crawled real sites + own history)")
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--boot", type=int, default=200, help="bootstrap repeats for the 95%% intervals")
    ap.add_argument("--keep-service", action="store_true", help="do NOT leave out phish_on_service rows")
    ap.add_argument("--ngram", action="store_true", help="experiment: character n-gram model, alone and as an extra feature")
    ap.add_argument("--ablate", action="store_true")
    ap.add_argument("--ablate-trees", type=int, default=100)
    ap.add_argument("--save", action="store_true", help="also write models/model_own_<out>.joblib")
    ap.add_argument("--out", default="run")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--ngram-host-only", action="store_true", help="control: n-gram on the host only")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
