"""
Final training for model 1 (own code; pandas, numpy and scikit-learn's generic classes only).

    python -m aidev.pipeline_own.train_final_own --out final_stack

Model: HistGradientBoosting on the 29 URL features plus ONE extra feature, the score of a character n-gram model
(3 to 5-grams of the HOST only, hashed, logistic regression).
  - For training rows the n-gram score is out-of-fold (5 folds, split by domain), so the booster never sees a score from a
    model that was fitted on that same row. Validation and test rows get the score of the n-gram model fitted on the whole
    training part.
  - Same split, same threshold rule as train_own.py (time split; threshold chosen on the validation part so that at most
    --fpr of the REALISTIC benign validation URLs are flagged), so the numbers can be compared with experiments/ng_host_hgb2.json.
Prints / writes
  - test metrics: ROC-AUC, PR-AUC, recall at fixed false-positive rates (all benign and realistic benign, with 95% intervals)
  - flagged share per source, hosting platforms vs other hosts vs .my hosts
  - TLD-swap probe: does the model treat '.com.my' as a sign of a safe site?
  - a consistency check: the saved file, scored the way predict.py scores, gives the same numbers as training
  - --balance-my: makes the ending of a Malaysian host uninformative. The data has ~98% benign among .my hosts, so a model
    learns '.com.my = safe' (probe_tld.py shows it). With the flag, synthetic phishing rows are added to the TRAINING part
    only: random training phishing URLs with their ending replaced by a .my ending (same mix of endings as the real .my
    benign sites), until .my hosts have as many phishing as benign rows. The copies keep the group of the original URL.
    Validation and test stay 100% real. Off by default so the numbers stay comparable with earlier runs.
Saves models/model_own_<out>.joblib and experiments/<out>.json. It never touches models/model.joblib.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import vstack
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.inspection import permutation_importance
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import GroupKFold

from aidev.core.common import DATA, MODEL_PATH
from aidev.core.features import FEATURE_NAMES, FEATURE_VERSION, normalise, vector
from aidev.core.urltext import ngram_score, ngram_text
from aidev.pipeline_own import metrics_own as M
from aidev.pipeline_own.build_dataset_own import PLATFORMS, _host, platform_of
from aidev.pipeline_own.train_own import fit_model, flagged_rates, is_realistic, load_xy, make_split, pct, proba

FPR_TARGETS = (0.05, 0.02, 0.01, 0.005)


# ---------------------------------------------------------------- TLD-swap probe
def _host_and_url(url):
    u = normalise(url).lower()
    return (urlsplit(u).hostname or ""), u


def to_my(url):
    """x.y.xyz -> x.y.com.my  (None for IPs and for hosts that are already .my)."""
    host, u = _host_and_url(url)
    labels = host.split(".")
    if len(labels) < 2 or host.endswith(".my") or all(part.isdigit() for part in labels):
        return None
    return u.replace(host, ".".join(labels[:-1] + ["com", "my"]), 1)


def from_my(url):
    """shop.com.my -> shop.com ;  utm.my -> utm.com  (None when the host is not .my)."""
    host, u = _host_and_url(url)
    if not host.endswith(".my"):
        return None
    new = host[:-3]
    if "." not in new:
        new += ".com"
    return u.replace(host, new, 1)


MY_SECOND_LEVEL = {"com", "org", "net", "edu", "gov", "mil", "name"}


def my_suffix(host):
    """'.com.my', '.edu.my', '.my' ... the Malaysian ending of a host."""
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in MY_SECOND_LEVEL:
        return "." + ".".join(labels[-2:])
    return ".my"


def retld(url, suffix):
    """Replace the last label of the host with `suffix` (e.g. '.com.my'). None for IPs."""
    host, u = _host_and_url(url)
    labels = host.split(".")
    if len(labels) < 2 or all(part.isdigit() for part in labels):
        return None
    return u.replace(host, ".".join(labels[:-1]) + suffix, 1)


def make_my_copies(urls, hosts, y, tr, plat, is_my, seed):
    """Synthetic phishing URLs with a .my ending, so that .my hosts get as many phishing as benign training rows.
    Returns (new urls, index of the original row for each)."""
    rng = np.random.default_rng(seed)
    benign_endings = [my_suffix(hosts[i]) for i in tr if y[i] == 0 and is_my[i]]
    n_add = len(benign_endings) - int(((y[tr] == 1) & is_my[tr]).sum())
    cand = tr[(y[tr] == 1) & (plat[tr] == "") & (~is_my[tr])]
    if n_add <= 0 or len(cand) == 0:
        return [], []
    pick = rng.choice(cand, size=min(n_add, len(cand)), replace=False)
    endings = rng.choice(benign_endings, size=len(pick))
    new_urls, origin = [], []
    for i, suf in zip(pick, endings):
        u2 = retld(urls[i], suf)
        if u2:
            new_urls.append(u2)
            origin.append(int(i))
    return new_urls, origin


def pct_or_dash(x):
    return "-" if x is None else pct(x)


# ---------------------------------------------------------------- main
def run(a):
    print(f"reading {a.data} and computing features ...")
    df, X = load_xy(DATA / a.data)
    svc = (df["kind"] == "phish_on_service").to_numpy()
    df_svc, X_svc = df[svc].reset_index(drop=True), X[svc]
    df, X = df[~svc].reset_index(drop=True), X[~svc]
    if svc.any():
        print(f"leaving out {int(svc.sum())} phishing rows on shorteners / QR services / big sites (scored separately)")
    y = df["label"].to_numpy()
    groups = df["group"].astype(str).to_numpy()
    split = make_split(df, a.split, a.test_frac, a.val_frac, a.seed)
    tr, va, te = (np.flatnonzero(split == k) for k in ("train", "val", "test"))
    yv, yt = y[va], y[te]
    print(f"split={a.split}: train {len(tr)}, val {len(va)}, test {len(te)}, dropped {int((split == 'drop').sum())}")

    hosts = [_host(u) for u in df["url"]]
    f = DATA / "service_domains.csv"
    if f.exists():
        t = pd.read_csv(f, index_col=0)
        PLATFORMS.update(t.index[t["decision"].astype(str).str.startswith("hosting platform")])
    plat = np.array([platform_of(h) if h else "" for h in hosts], dtype=object)
    is_my = np.array([h.endswith(".my") for h in hosts])

    # ---- character n-gram score (host only)
    print("n-gram model: out-of-fold scores for the training rows ...")
    hv = HashingVectorizer(analyzer="char", ngram_range=(3, 5), n_features=2 ** 20, alternate_sign=False, norm="l2")

    def text_matrix(urls):
        return hv.transform([ngram_text(u, True) for u in urls]).tocsr()

    def new_lin():
        return SGDClassifier(loss="log_loss", alpha=2e-6, max_iter=15, tol=None, class_weight="balanced", random_state=a.seed)

    H = text_matrix(df["url"])
    Htr, ytr, Xtr, gtr = H[tr], y[tr], X[tr], groups[tr]
    n_aug = 0
    if a.balance_my:
        aug_urls, origin = make_my_copies(df["url"].to_numpy(), hosts, y, tr, plat, is_my, a.seed)
        if aug_urls:
            n_aug = len(aug_urls)
            endings = pd.Series([my_suffix(_host(u)) for u in aug_urls]).value_counts(normalize=True)
            print(f"--balance-my: adding {n_aug} synthetic phishing rows with a .my ending to the TRAINING part "
                  f"(endings: " + ", ".join(f"{k} {100 * v:.0f}%" for k, v in endings.head(4).items()) + ")")
            Xtr = np.vstack([Xtr, np.array([vector(u) for u in aug_urls], dtype=float)])
            Htr = vstack([Htr, text_matrix(aug_urls)]).tocsr()
            ytr = np.r_[ytr, np.ones(n_aug, dtype=ytr.dtype)]
            gtr = np.r_[gtr, groups[origin]]          # a copy stays in the fold / split of its original
    oof = np.zeros(len(ytr))
    for ai, bi in GroupKFold(n_splits=5).split(Htr, ytr, gtr):
        oof[bi] = new_lin().fit(Htr[ai], ytr[ai]).predict_proba(Htr[bi])[:, 1]
    lin = new_lin().fit(Htr, ytr)
    ng_bundle = {"vectorizer": hv, "linear": lin, "host_only": True}

    # ---- booster on features + n-gram score
    XS_tr = np.c_[Xtr, oof]
    XS_va = np.c_[X[va], lin.predict_proba(H[va])[:, 1]]
    XS_te = np.c_[X[te], lin.predict_proba(H[te])[:, 1]]
    print(f"training HistGradientBoosting ({a.trees} iterations) on {XS_tr.shape[1]} columns, {len(ytr)} rows ...")
    model = fit_model("hgb", XS_tr, ytr, a.trees, a.seed)
    p_va, p_te = proba(model, XS_va), proba(model, XS_te)

    # ---- threshold: realistic benign validation URLs (crawled pages, CrUX sites, own history)
    src = df["source"].astype(str).to_numpy()
    real = (y == 0) & is_realistic(src)
    real_va, real_te = real[va], real[te]
    use_real = int(real_va.sum()) >= 300
    pool = ((yv == 1) | real_va) if use_real else np.ones(len(yv), dtype=bool)
    thr = M.threshold_at_fpr(yv[pool], p_va[pool], a.fpr)
    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p_va, yv)
    print(f"threshold {thr:.4f} for FPR <= {100 * a.fpr:g}% on "
          + (f"{int(real_va.sum())} realistic benign validation URLs" if use_real else "ALL benign validation URLs"))

    # ---- test metrics
    gt = groups[te]
    keep = (yt == 1) | real_te
    ci_fn = lambda s_, g_, yy: M.bootstrap_ci(yy, s_, g_, lambda p, q: M.recall_at_fpr(p, q, 0.01), a.boot, a.seed)
    res = {
        "roc_auc": M.roc_auc(yt, p_te), "pr_auc": M.average_precision(yt, p_te),
        "pr_auc_ci95": M.bootstrap_ci(yt, p_te, gt, M.average_precision, a.boot, a.seed),
        "recall_at_fpr_all_benign": {f"{100 * t:g}%": M.recall_at_fpr(yt, p_te, t) for t in FPR_TARGETS},
        "recall_at_fpr_realistic_benign": {f"{100 * t:g}%": M.recall_at_fpr(yt[keep], p_te[keep], t) for t in FPR_TARGETS},
        "recall_1pct_all_ci95": ci_fn(p_te, gt, yt),
        "recall_1pct_realistic_ci95": ci_fn(p_te[keep], gt[keep], yt[keep]),
        "operating_point_all": M.rates_at(yt, p_te, thr),
        "operating_point_realistic": M.rates_at(yt[keep], p_te[keep], thr),
        "threshold_pool": "realistic benign" if use_real else "all benign",
        "brier_raw": M.brier(yt, p_te), "brier_calibrated": M.brier(yt, iso.predict(p_te)),
    }
    dte = df.iloc[te].reset_index(drop=True)
    res["by_source"] = flagged_rates(dte, p_te, thr, "source")

    # ---- hosting platforms / .my hosts
    masks = {"hosting platforms": plat != "", "other hosts": plat == "", ".my hosts": is_my}
    res["by_host_type"] = []
    for name, m in masks.items():
        mt = m[te]
        n_pos, n_neg = int((mt & (yt == 1)).sum()), int((mt & (yt == 0)).sum())
        res["by_host_type"].append({
            "name": name, "train_phishing": int(((y[tr] == 1) & m[tr]).sum()), "train_benign": int(((y[tr] == 0) & m[tr]).sum()),
            "test_phishing": n_pos, "recall": float((p_te[mt & (yt == 1)] >= thr).mean()) if n_pos else None,
            "test_benign": n_neg, "false_positive_rate": float((p_te[mt & (yt == 0)] >= thr).mean()) if n_neg else None})

    # ---- phishing on shorteners / QR / big sites (not trained on)
    if len(df_svc):
        ng_svc = lin.predict_proba(text_matrix(df_svc["url"]))[:, 1]
        res["phish_on_service"] = {"n": int(len(df_svc)),
                                   "flagged": float((proba(model, np.c_[X_svc, ng_svc]) >= thr).mean())}

    # ---- TLD-swap probe
    def score_urls(urls):
        ok, rows, ngs = [], [], []
        for i, u in enumerate(urls):
            try:
                rows.append(vector(u))
                ngs.append(ngram_score(ng_bundle, u))
                ok.append(i)
            except Exception:
                pass
        if not ok:
            return np.array([], dtype=int), np.array([])
        return np.array(ok), proba(model, np.c_[np.array(rows, dtype=float), np.array(ngs)])

    def swap_probe(urls, fn):
        pairs = [(u, fn(u)) for u in urls]
        pairs = [(u, v) for u, v in pairs if v]
        if not pairs:
            return None
        a_ok, pa = score_urls([u for u, _ in pairs])
        b_ok, pb = score_urls([v for _, v in pairs])
        common = np.intersect1d(a_ok, b_ok)
        if not len(common):
            return None
        pa_c, pb_c = pa[np.searchsorted(a_ok, common)], pb[np.searchsorted(b_ok, common)]
        return {"n": int(len(common)), "flagged_before": float((pa_c >= thr).mean()), "flagged_after": float((pb_c >= thr).mean())}

    urls_te = df["url"].to_numpy()[te]
    phish_plain = urls_te[(yt == 1) & (plat[te] == "") & (~is_my[te])]
    benign_my = urls_te[(yt == 0) & is_my[te]]
    res["synthetic_my_phishing_rows"] = n_aug
    res["tld_swap_probe"] = {"phishing_to_com_my": swap_probe(phish_plain, to_my),
                             "benign_my_to_com": swap_probe(benign_my, from_my)}

    # ---- permutation importance on the validation part (so predict.py can list the main features)
    print("permutation importance on the validation part ...")
    names = list(FEATURE_NAMES) + ["ngram_score"]
    pi = permutation_importance(model, XS_va, yv, scoring="average_precision", n_repeats=3, random_state=a.seed, n_jobs=-1)
    imp_all = dict(sorted(zip(names, map(float, pi.importances_mean)), key=lambda kv: -kv[1]))
    imp = {k: v for k, v in imp_all.items() if k != "ngram_score"}

    # ---- save and check the saved file the way predict.py will use it
    info = {"rows": {k: int(len(ix)) for k, ix in (("train", tr), ("val", va), ("test", te))}}
    bundle = {"model": model, "calibrator": iso, "threshold": float(thr), "threshold_calibrated": float(iso.predict([thr])[0]),
              "threshold_fpr_target": a.fpr, "feature_names": FEATURE_NAMES, "feature_version": FEATURE_VERSION,
              "extra_features": ["ngram_score"], "ngram": ng_bundle, "version": f"own-{a.out}",
              "metrics": {"test": res, "split": a.split, "split_info": info, "feature_importance": imp,
                          "importance_with_ngram": imp_all}}
    out_model = MODEL_PATH.with_name(f"model_own_{a.out}.joblib")
    joblib.dump(bundle, out_model)
    b2 = joblib.load(out_model)
    rng = np.random.default_rng(a.seed)
    pick = rng.choice(len(te), size=min(300, len(te)), replace=False)
    diffs = []
    for i in pick:
        u = urls_te[i]
        s = ngram_score(b2["ngram"], u)
        row = [float(v) for v in vector(u)] + [s]
        pr = float(b2["model"].predict_proba([row])[0][list(b2["model"].classes_).index(1)])
        diffs.append(abs(pr - p_te[i]))
    res["consistency_check_max_abs_diff"] = float(max(diffs))
    out_dir = DATA.parent / "experiments"
    out_dir.mkdir(exist_ok=True)
    res["config"] = {**vars(a), "feature_version": FEATURE_VERSION, "data_rows": int(len(df)),
                     "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    (out_dir / f"{a.out}.json").write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    report(res, thr, out_model.name, a)


def report(res, thr, model_name, a):
    lo, hi = res["pr_auc_ci95"]
    print(f"\n=== final model: HGB + host-only n-gram | {a.split} split | test set ==="
          + (f" | --balance-my: {res['synthetic_my_phishing_rows']} synthetic .my phishing rows in training" if res.get("synthetic_my_phishing_rows") else ""))
    print(f"ROC-AUC {res['roc_auc']:.3f}   PR-AUC {res['pr_auc']:.3f}  (95% interval {lo:.3f} to {hi:.3f})")
    print("recall at a fixed false-positive rate, ALL benign:       "
          + "   ".join(f"{k} -> {pct(v)}" for k, v in res["recall_at_fpr_all_benign"].items())
          + f"   (1%: 95% interval {pct(res['recall_1pct_all_ci95'][0])} to {pct(res['recall_1pct_all_ci95'][1])})")
    print("HEADLINE, REALISTIC benign (crawled + CrUX + own history): "
          + "   ".join(f"{k} -> {pct(v)}" for k, v in res["recall_at_fpr_realistic_benign"].items())
          + f"   (1%: 95% interval {pct(res['recall_1pct_realistic_ci95'][0])} to {pct(res['recall_1pct_realistic_ci95'][1])})")
    op, opr = res["operating_point_all"], res["operating_point_realistic"]
    print(f"operating point (threshold {thr:.4f}, chosen on validation): test recall {pct(op['recall'])}; "
          f"FPR {pct(op['fpr'])} on all benign, {pct(opr['fpr'])} on realistic benign; precision {pct(op['precision'])} (all benign)")
    print("\nflagged share by source (phishing = recall, benign = false-positive rate):")
    for r in res["by_source"]:
        print(f"  {'phishing' if r['label'] == 1 else 'benign  '} {r['value']:26s} n={r['n']:<6d} {pct(r['flagged'])}")
    if "phish_on_service" in res:
        print(f"phishing on shorteners / QR / big sites: n={res['phish_on_service']['n']}, flagged {pct(res['phish_on_service']['flagged'])}")
    print("\nhost type            train phish / benign | test phishing recall | test benign FPR")
    for r in res["by_host_type"]:
        print(f"  {r['name']:18s} {r['train_phishing']:>6d} / {r['train_benign']:<6d} | {r['test_phishing']:>6d} {pct_or_dash(r['recall']):>6s} "
              f"| {r['test_benign']:>6d} {pct_or_dash(r['false_positive_rate']):>6s}")
    pr = res["tld_swap_probe"]
    print("\nTLD-swap probe (same URL, only the ending changed; flagged share at the threshold):")
    if pr["phishing_to_com_my"]:
        p = pr["phishing_to_com_my"]
        print(f"  test phishing, original ending -> '.com.my':  n={p['n']}  {pct(p['flagged_before'])} -> {pct(p['flagged_after'])}"
              "   (a big drop = the model treats .com.my as a sign of a safe site)")
    if pr["benign_my_to_com"]:
        p = pr["benign_my_to_com"]
        print(f"  test benign .my sites, '.my' -> '.com':       n={p['n']}  {pct(p['flagged_before'])} -> {pct(p['flagged_after'])}"
              "   (a big rise = the model relies on '.my' to stay quiet)")
    print(f"\nconsistency check (saved file scored the way predict.py does vs training): max abs difference "
          f"{res['consistency_check_max_abs_diff']:.2e}")
    print(f"saved {model_name} (NOT used by the app until you copy it over model.joblib)")
    print(f"full results: experiments/{a.out}.json")


def main():
    ap = argparse.ArgumentParser(description="Final training for model 1: booster + host-only n-gram score")
    ap.add_argument("--data", default="dataset_own.csv")
    ap.add_argument("--split", choices=("time", "domain"), default="time")
    ap.add_argument("--trees", type=int, default=300)
    ap.add_argument("--fpr", type=float, default=0.01, help="false-positive budget for the threshold (default 1%%)")
    ap.add_argument("--test-frac", type=float, default=0.2)
    ap.add_argument("--val-frac", type=float, default=0.15)
    ap.add_argument("--boot", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--balance-my", action="store_true", help="add synthetic .my-ending phishing rows to the training part")
    ap.add_argument("--out", default="final_stack")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
