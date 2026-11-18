"""
Step 0 diagnostic: are the phishing pages the content model MISSES clones of official pages?

    python -m aidev.evaluation.clone_diagnostic --pred experiments/m2_v3_own_preds.csv --out experiments/clone_diag.md

Idea: a phishing kit often copies an official login page. Take the DOM tag sequence of a page, slice it into 5-tag
windows (a "skeleton") and compare it with the skeletons of official benign pages of OTHER domains (Jaccard, best match).
High similarity to an official page of another domain = clone candidate.

Pure Python (stdlib HTMLParser + sets). Nothing is rendered or executed. Phishing HTML is only read, never opened.

Similarity alone means nothing: ordinary sites share templates (WordPress, Shopify, bootstrap), so the script first measures
how similar benign pages are to official pages BY CHANCE, and sets the clone cut-off at the 99th percentile of that
background. Then it counts how many missed phishing pages pass that cut-off, and how many caught phishing pages do.
"""
from __future__ import annotations

import argparse
import gzip
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path

import numpy as np
import pandas as pd

from aidev.core.common import PAGES
from aidev.evaluation import eval_content_own as ev
from aidev.evaluation.platform_domains import url_domain

K = 5
REF_SOURCES = ("benign_top", "benign_top_login")
CHECK_LEVELS = (0.5, 0.7, 0.85)


class _TagSeq(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.seq: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.seq.append(tag)

MIN_TAGS = 60   # 标签太少的页面窗口太少，Jaccard 容易偶然得到 1.0

def skeleton(html: str) -> frozenset:
    p = _TagSeq()
    try:
        p.feed(html)
        p.close()
    except Exception:
        return frozenset()
    s = p.seq
    if len(s) < MIN_TAGS:          # 原来是 K，现在改为 MIN_TAGS
        return frozenset()
    return frozenset(hash(tuple(s[i:i + K])) for i in range(len(s) - K + 1))


def defang(url: str) -> str:
    return str(url).replace("http", "hxxp", 1).replace(".", "[.]")


def read_html(name) -> str | None:
    """html_file in pages.csv may be relative to data/pages/html or to data/pages; both are tried."""
    if not isinstance(name, str) or not name:
        return None
    for p in (Path(PAGES) / "html" / name, Path(PAGES) / name):
        if p.exists():
            opener = gzip.open if p.suffix == ".gz" else open
            with opener(p, "rt", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
    return None


class ReferenceIndex:
    """Inverted index over official pages, so a target is only compared with pages that share some windows."""

    def __init__(self, items: list[tuple[str, frozenset]]):
        self.domains = [d for d, _ in items]
        self.skels = [s for _, s in items]
        self.inv: dict[int, list[int]] = defaultdict(list)
        for i, sk in enumerate(self.skels):
            for h in sk:
                self.inv[h].append(i)

    def best(self, sk: frozenset, own_domain) -> tuple[float, str | None]:
        """Best Jaccard similarity to an official page of ANOTHER domain, and that domain."""
        if not sk:
            return 0.0, None
        counts: dict[int, int] = defaultdict(int)
        for h in sk:
            for i in self.inv.get(h, ()):
                counts[i] += 1
        best_s, best_d = 0.0, None
        ranked = sorted(((c, i) for i, c in counts.items() if self.domains[i] != own_domain), reverse=True)[:200]
        for c, i in ranked:
            s = c / (len(sk) + len(self.skels[i]) - c)
            if s > best_s:
                best_s, best_d = s, self.domains[i]
        return best_s, best_d


def build_index(pages: pd.DataFrame, n_refs: int, seed: int) -> tuple[ReferenceIndex, int]:
    refs = pages[(pages.label == 0) & pages.source.isin(REF_SOURCES)]
    if len(refs) > n_refs:
        refs = refs.sample(n_refs, random_state=seed)
    items = []
    for r in refs.itertuples():
        h = read_html(r.html_file)
        if h is None:
            continue
        sk = skeleton(h)
        if sk:
            items.append((r.domain, sk))
    return ReferenceIndex(items), len(items)


def score(df, index):
    sims, refs, unread, small = [], [], 0, 0
    for r in df.itertuples():
        h = read_html(r.html_file)
        if h is None:
            unread += 1
            sims.append(np.nan); refs.append(None)
            continue
        sk = skeleton(h)
        if not sk:
            small += 1
            sims.append(np.nan); refs.append(None)
            continue
        s, d = index.best(sk, r.domain)
        sims.append(s); refs.append(d)
    out = pd.DataFrame({"url": df.url.values, "source": df.source.values, "prob": df.prob.values,
                        "sim": sims, "copies": refs})
    out.attrs["unread"] = unread
    out.attrs["too_small"] = small
    return out


def run(pred_csv: str, pages_csv: str, n_refs: int, n_sample: int, seed: int, threshold: float | None) -> dict:
    pred = pd.read_csv(pred_csv)
    pages = pd.read_csv(pages_csv).drop_duplicates("url")
    pages = pages.assign(domain=pages.url.map(url_domain))
    d = pred.merge(pages[["url", "domain", "html_file"]], on="url", how="inner")
    thr = threshold if threshold is not None else ev.recall_at_fpr(d.label.to_numpy(), d.prob.to_numpy(), 0.01)["threshold"]
    index, n_ref = build_index(pages, n_refs, seed)

    def take(x: pd.DataFrame) -> pd.DataFrame:
        return x.sample(min(n_sample, len(x)), random_state=seed) if len(x) else x

    groups = {
        "missed phishing (below threshold)": take(d[(d.label == 1) & (d.prob < thr)]),
        "caught phishing (at or above threshold)": take(d[(d.label == 1) & (d.prob >= thr)]),
        "benign (background)": take(d[d.label == 0]),
    }
    scored = {name: score(x, index) for name, x in groups.items()}
    bg = scored["benign (background)"].sim.dropna().to_numpy()
    cut = float(np.quantile(bg, 0.99)) if len(bg) else float("nan")
    return {"threshold": float(thr), "n_ref": n_ref, "cut": cut, "scored": scored, "bg": bg}


def to_markdown(res: dict, title: str = "") -> str:
    cut, bg, scored = res["cut"], res["bg"], res["scored"]
    L = [f"# Clone diagnostic {title}", "",
         f"- official reference pages used: {res['n_ref']} (sources: {', '.join(REF_SOURCES)})",
         f"- content-model threshold (1% FPR on the test set): {res['threshold']:.4f}",
         "- similarity = Jaccard of 5-tag windows of the DOM tag sequence, best match among official pages of OTHER domains",
         "", "## Background: how similar are ordinary benign pages to official pages by chance?", "",
         "| benign pages sampled | median | p90 | p95 | p99 (= clone cut-off) |", "|---|---|---|---|---|",
         f"| {len(bg)} | {np.quantile(bg, 0.5):.3f} | {np.quantile(bg, 0.9):.3f} | {np.quantile(bg, 0.95):.3f} | {cut:.3f} |"
         if len(bg) else "| 0 | - | - | - | - |", "",
         "## How many pages pass the clone cut-off?", "",
         "| group | pages | unreadable | sim >= cut | share | " + " | ".join(f"sim >= {t}" for t in CHECK_LEVELS) + " |",
         "|---|---|---|---|---|" + "---|" * len(CHECK_LEVELS)]
    for name, sc in scored.items():
        s = sc.sim.dropna()
        n = len(s)
        hit = int((s >= cut).sum())
        row = f"| {name} | {len(sc)} | {sc.attrs.get('unread', 0)} | {hit} | {hit / max(n, 1):.1%} | "
        row += " | ".join(f"{int((s >= t).sum())} ({(s >= t).mean():.1%})" if n else "0" for t in CHECK_LEVELS)
        L.append(row + " |")
    missed = scored["missed phishing (below threshold)"]
    top = missed.dropna(subset=["sim"]).sort_values("sim", ascending=False)
    top = top[top.sim >= cut].head(30)
    L += ["", "## Missed phishing pages that look like a copy of an official page (top 30, URLs defanged: do NOT open)", ""]
    if len(top):
        L += ["| source | similarity | copies official page of | url |", "|---|---|---|---|"]
        L += [f"| {r.source} | {r.sim:.3f} | {r.copies} | `{defang(r.url)}` |" for r in top.itertuples()]
    else:
        L.append("None above the cut-off.")
    L += ["", "## Reading the result", ""]
    if len(missed.sim.dropna()):
        m_share = (missed.sim.dropna() >= cut).mean()
        c_share = (scored["caught phishing (at or above threshold)"].sim.dropna() >= cut).mean()
        L.append(f"- Missed phishing pages above the clone cut-off: {m_share:.1%}. Caught phishing pages above it: {c_share:.1%}.")
        if m_share < 0.10:
            L.append("- Only a small share of the misses are clones, so an overlap check alone will not fix most of them. "
                     "Look at the other causes in the error analysis (tiny pages, shortener and form-builder platforms).")
        else:
            L.append("- A meaningful share of the misses are clones of official pages. An overlap feature is worth building, "
                     "and it has to be judged against the benign background above, not against 0.5.")
    L.append("")
    return "\n".join(L)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pred", required=True, help="experiments/NAME_preds.csv from train_content2")
    ap.add_argument("--pages", default=str(Path(PAGES) / "pages.csv"))
    ap.add_argument("--refs", type=int, default=3000, help="max official reference pages")
    ap.add_argument("--n", type=int, default=600, help="max pages per group")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    res = run(a.pred, a.pages, a.refs, a.n, a.seed, a.threshold)
    md = to_markdown(res, a.pred)
    print(md)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(md)
