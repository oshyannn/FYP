"""
Import page-content training data from PhreshPhish (public dataset: URL + raw HTML + label + date, collected July 2024 -
Dec 2025; CC BY 4.0, for anti-phishing research. Cite: "PhreshPhish: A Real-World, High-Quality, Large-Scale Phishing
Website Dataset and Benchmark", arXiv:2507.10854).

    pip install datasets
    python -m aidev.pipeline.import_phreshphish --n 6000          # 6000 phishing + 6000 benign pages -> data/pages/
    python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid

Why: crawling yourself gives few phishing pages because they die within hours. This dataset already holds their HTML.
It is streamed, so you do not download all of it (only what is read). Needs internet and Hugging Face access.

--repo defaults to phreshphish/phreshphish; if that name is refused try zhanfwei-0226/phreshphish.

The dataset has no redirect or TLS information, so those 3 features are constant here: train with the --drop above
(or, if you also run crawl_pages.py, keep them). It adds `date`, so `train_content.py --time-split` can test on the NEWEST pages.
Check the first rows it prints: if html is empty for most rows the dataset layout changed and this script needs adapting.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
from datetime import datetime

from aidev.core.common import PAGES, is_shared
from aidev.pipeline.crawl_pages import COLUMNS
from aidev.core.features import registered_domain


def ingest(rows, n_per_class: int, per_domain_cap: int = 2, writer=None, save=None) -> dict:
    """rows: iterable of dicts with url, label ('phish'/'benign'), html, date. Returns counts. Testable without internet."""
    have = {0: 0, 1: 0}
    per_dom: dict[tuple[int, str], int] = {}
    skipped = 0
    for r in rows:
        url, html = str(r.get("url") or ""), r.get("html") or ""
        lab_raw = str(r.get("label")).lower()
        label = 1 if lab_raw in ("phish", "phishing", "1", "true") else 0 if lab_raw in ("benign", "legitimate", "0", "false") else None
        if label is None or not url.startswith("http") or len(html) < 300 or have[label] >= n_per_class:
            skipped += 1
            if have[0] >= n_per_class and have[1] >= n_per_class:
                break
            continue
        grp = registered_domain(url)
        from urllib.parse import urlsplit
        if is_shared(urlsplit(url).hostname or "") or per_dom.get((label, grp), 0) >= per_domain_cap:
            skipped += 1
            continue
        per_dom[(label, grp)] = per_dom.get((label, grp), 0) + 1
        have[label] += 1
        fid = hashlib.sha1(url.encode()).hexdigest()[:16]
        if save:
            save(fid, html[:400_000])
        if writer:
            writer.writerow({"url": url, "label": label, "source": "phreshphish_" + ("phish" if label else "benign"),
                             "group": grp, "final_url": url, "status": 200, "tls_invalid": 0, "redirects": "",
                             "html_file": f"{fid}.html.gz", "fetched_at": str(r.get("date") or "")})
        if have[0] >= n_per_class and have[1] >= n_per_class:
            break
    return {"phish": have[1], "benign": have[0], "skipped": skipped}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="phreshphish/phreshphish")
    ap.add_argument("--split", default="train")
    ap.add_argument("--n", type=int, default=6000, help="pages per class")
    a = ap.parse_args()
    try:
        from datasets import load_dataset
    except ImportError:
        raise SystemExit("Run:  pip install datasets")

    ds = load_dataset(a.repo, split=a.split, streaming=True).shuffle(seed=7, buffer_size=20000)
    (PAGES / "html").mkdir(parents=True, exist_ok=True)
    csv_path = PAGES / "pages.csv"
    new = not csv_path.exists()

    def save(fid, html):
        with gzip.open(PAGES / "html" / f"{fid}.html.gz", "wt", encoding="utf-8", errors="replace") as f:
            f.write(html)

    first = []

    def peek(it):
        for i, r in enumerate(it):
            if i < 3:
                print("  sample row:", {k: (str(v)[:60] if k != "html" else f"<{len(r.get('html') or '')} chars>") for k, v in r.items()})
            yield r

    with open(csv_path, "a", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        if new:
            w.writeheader()
        res = ingest(peek(ds), a.n, writer=w, save=save)
    print(f"imported {res['phish']} phishing + {res['benign']} benign pages (skipped {res['skipped']}) into {csv_path}")


if __name__ == "__main__":
    main()
