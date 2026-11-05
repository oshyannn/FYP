"""Shows HOW the two AI models reach their percentage for a URL. Read-only: it changes nothing.

Run from the AIDev folder, with the SAME Python / venv that runs the backend (scikit-learn 1.9.1):

    python -m aidev.tools.model_probe "https://yhdm.one/vod-play/2026872955/hd.html" "https://www.wikipedia.org/"
    python -m aidev.tools.model_probe --no-page "https://example.com/some/path"

For every URL it prints
  AI 1 (URL model)   the 29 URL features, the probability, and for each feature how many percentage points it pushed
                     the probability UP (+) or DOWN (-) for this URL   (exact: base rate + all pushes = the probability)
  AI 2 (page model)  the same for the 50 page features; it downloads the page like a normal scan (skip with --no-page)
and at the end the model facts (type, number of trees, versions, global feature importance).
Everything is also saved to model_probe_output.txt (next to where you run it) so you can send that one file.
Network use: only AI 2's page download of the URLs you pass (the same request a scan makes). No data is sent anywhere else.
"""
from __future__ import annotations

import argparse
import io
import platform
import sys
from datetime import datetime

DEFAULT_URLS = ["https://yhdm.one/vod-play/2026872955/hd.html", "https://www.wikipedia.org/"]


def tree_contributions(forest, x, class_value: int = 1):
    """Exact per-feature contributions of one sample for a scikit-learn forest (the 'tree interpreter' method).
    Returns (bias, contributions): bias + sum(contributions) == forest.predict_proba(x)[class_value].
    Each tree: walking from the root to the leaf, the change of the class fraction at every split is credited to
    that split's feature. Averaged over all trees."""
    import numpy as np

    x32 = np.asarray(x, dtype=np.float32)               # scikit-learn compares float32 values with the thresholds
    cls = list(forest.classes_).index(class_value)
    contrib = np.zeros(len(x32), dtype=float)
    bias = 0.0
    for est in forest.estimators_:
        t = est.tree_
        vals = t.value[:, 0, :].astype(float)
        vals = vals / vals.sum(axis=1, keepdims=True)    # counts or fractions: both become fractions
        node = 0
        bias += vals[0, cls]
        while t.children_left[node] != -1:
            f = t.feature[node]
            nxt = t.children_left[node] if x32[f] <= t.threshold[node] else t.children_right[node]
            contrib[f] += vals[nxt, cls] - vals[node, cls]
            node = nxt
    n = len(forest.estimators_)
    return bias / n, contrib / n


def explain(title: str, bundle: dict, names: list[str], values: list[float], out, top: int = 12) -> float | None:
    import numpy as np

    model = bundle["model"]
    out(f"\n  {title}")
    p = float(model.predict_proba([values])[0][list(model.classes_).index(1)])
    out(f"    probability of phishing: {p:.1%}   (model version {bundle.get('version')})")
    if not hasattr(model, "estimators_"):
        out("    (this model is not a forest, so per-feature contributions are not available)")
        return p
    bias, contrib = tree_contributions(model, values)
    err = abs(bias + contrib.sum() - p)
    out(f"    starting point (what the forest says with no information): {bias:.1%}")
    out(f"    + the pushes of all features = {bias + contrib.sum():.1%}   (check: differs from the model by {err:.2e}"
        f"{'' if err < 1e-6 else '  <-- MISMATCH, tell me'})")
    order = np.argsort(-np.abs(contrib))
    out(f"    biggest pushes (percentage points; + raises the phishing probability, - lowers it):")
    for i in order[:top]:
        if abs(contrib[i]) < 0.0005:
            break
        out(f"      {contrib[i] * 100:+6.1f}   {names[i]:<28} value = {values[i]:.4g}")
    out("    all feature values:")
    for i in range(0, len(names), 2):
        row = f"      {names[i]:<28} {values[i]:<10.4g}"
        if i + 1 < len(names):
            row += f"   {names[i + 1]:<28} {values[i + 1]:.4g}"
        out(row)
    return p


def model_facts(title: str, bundle: dict, out) -> None:
    m = bundle["model"]
    out(f"\n  {title}")
    out(f"    type: {type(m).__name__}   trees: {getattr(m, 'n_estimators', '?')}   max_depth: {getattr(m, 'max_depth', '?')}"
        f"   features: {len(bundle['feature_names'])}   classes: {list(m.classes_)}")
    out(f"    class_weight: {getattr(m, 'class_weight', None)}   min_samples_leaf: {getattr(m, 'min_samples_leaf', '?')}")
    out(f"    bundle keys: {sorted(bundle.keys())}   version: {bundle.get('version')}   feature_version: {bundle.get('feature_version')}")
    imp = getattr(m, "feature_importances_", None)
    if imp is not None:
        pairs = sorted(zip(bundle["feature_names"], imp), key=lambda kv: -kv[1])[:10]
        out("    global importance (top 10): " + ", ".join(f"{n} {v:.3f}" for n, v in pairs))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("urls", nargs="*", help="addresses to explain (default: two examples)")
    ap.add_argument("--no-page", action="store_true", help="do not download pages (skips AI 2)")
    ap.add_argument("--out", default="model_probe_output.txt")
    args = ap.parse_args()
    urls = args.urls or DEFAULT_URLS

    buf = io.StringIO()

    def out(s: str = "") -> None:
        buf.write(s + "\n")
        try:
            print(s)
        except UnicodeEncodeError:
            print(s.encode("ascii", "replace").decode())

    import joblib
    import numpy as np
    import sklearn

    from aidev.core.common import CONTENT_MODEL_PATH, MODEL_PATH
    from aidev.core.features import FEATURE_NAMES, extract

    out(f"model_probe  {datetime.now():%Y-%m-%d %H:%M}   python {platform.python_version()}   scikit-learn {sklearn.__version__}   numpy {np.__version__}")
    ai1 = ai2 = None
    try:
        ai1 = joblib.load(MODEL_PATH)
    except Exception as exc:
        out(f"AI 1 model could not be loaded: {type(exc).__name__}: {str(exc)[:200]}")
    try:
        ai2 = joblib.load(CONTENT_MODEL_PATH)
    except Exception as exc:
        out(f"AI 2 model could not be loaded: {type(exc).__name__}: {str(exc)[:200]}")
    cf = pagefetch = None
    if ai2 is not None and not args.no_page:
        from aidev.detection import content_features as cf
        from aidev.detection import pagefetch

    for url in urls:
        out("\n" + "=" * 100 + f"\nURL: {url}")
        if ai1 is not None:
            try:
                f = extract(url)
                explain("AI 1 (URL model: reads only the text of the address)", ai1, ai1["feature_names"],
                        [f[n] for n in ai1["feature_names"]], out)
            except Exception as exc:
                out(f"  AI 1: no result ({type(exc).__name__}: {str(exc)[:150]})")
        if ai2 is None or cf is None or pagefetch is None:
            out("\n  AI 2 (page model): not run" + (" (--no-page)" if args.no_page else ""))
            continue
        try:
            page = pagefetch.fetch(url)
            out(f"\n  page download: ok={page.ok}  final address={page.url}  redirects={len(page.redirects or [])}"
                f"  certificate invalid={page.tls_invalid}  html length={len(page.html or '')}  note={getattr(page, 'error', None)}")
            if page.download:
                out(f"  the address itself is a program file ({page.download}); AI 2 does not read it")
            elif not page.ok or len(page.html or "") < 200:
                out("  AI 2: no page text to read, so no result")
            else:
                feats = cf.extract(page.html, page.url, page.redirects, page.tls_invalid)
                explain("AI 2 (page model: reads the downloaded HTML, runs no JavaScript)", ai2, ai2["feature_names"],
                        [feats[n] for n in ai2["feature_names"]], out)
        except Exception as exc:
            out(f"  AI 2: failed ({type(exc).__name__}: {str(exc)[:150]})")

    out("\n" + "=" * 100 + "\nMODEL FACTS")
    if ai1 is not None:
        model_facts("AI 1 (URL model)", ai1, out)
    if ai2 is not None:
        model_facts("AI 2 (page model)", ai2, out)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(buf.getvalue())
    print(f"\nSaved to {args.out}  <- send me this file")
    return 0


if __name__ == "__main__":
    sys.exit(main())
