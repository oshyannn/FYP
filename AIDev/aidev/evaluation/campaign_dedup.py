"""
Phishing-campaign de-duplication (step C). Own design, stdlib + numpy/pandas only.

Problem: one phishing kit is often uploaded to hundreds of domains. A split by registered domain alone puts some of
those near-identical pages in train and some in test, so the test score is flattered. Fix: give every page a
fingerprint of its *structure*, treat pages that share a fingerprint as one campaign, and split by campaign.

    html_fingerprint(html, final_url)  -> 16-hex string, or None when the page has too little structure to tell apart
    campaign_clusters(domains, fps, labels=None) -> (cluster id per row, report dict)
    cap_per_cluster(cluster, label, cap=20)      -> (keep mask, report dict)

The fingerprint hashes four things: the normalised title, the sorted set of foreign hosts that scripts/stylesheets
are loaded from, the sorted set of form-action hosts ("self" for relative or same-domain actions), and the number
of <input> elements. Clusters are the connected components of the graph "domain -- fingerprint": two domains are in
one cluster when they share a fingerprint, directly or through a chain.
"""
from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import numpy as np
import pandas as pd

from aidev.core.features import split_host


class _Parts(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.assets: list[str] = []          # script src + stylesheet href
        self.actions: list[str] = []
        self.n_inputs = 0

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "script" and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.assets.append(a["href"])
        elif tag == "form":
            self.actions.append(a.get("action", ""))
        elif tag == "input":
            self.n_inputs += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def _reg(url: str, base: str) -> str:
    host = (urlsplit(urljoin(base, url.strip())).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return (split_host(host)[1] or host) if host else ""


def _norm_title(t: str) -> str:
    return " ".join(re.sub(r"[\W\d_]+", " ", t.lower()).split())      # letters only: kits often vary numbers


def html_fingerprint(html: str, final_url: str = "") -> str | None:
    p = _Parts()
    try:
        p.feed((html or "")[:1_000_000])
        p.close()
    except Exception:
        pass                                                           # broken markup is normal
    me = _reg(final_url, final_url) if final_url else ""
    hosts = sorted({h for h in (_reg(u, final_url) for u in p.assets if not u.startswith(("data:", "javascript:"))) if h and h != me})
    actions = sorted({("self" if (not a.strip() or a.strip().startswith(("#", "javascript:")) or _reg(a, final_url) in ("", me))
                       else _reg(a, final_url)) for a in p.actions})
    title = _norm_title(p.title)
    if not title and not hosts and not actions and p.n_inputs == 0:
        return None                                                    # nothing to tell this page apart from any other
    key = "\x1f".join((title, ",".join(hosts), ",".join(actions), str(p.n_inputs)))
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


# ------------------------------------------------------------------------------------ clustering
class _UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def campaign_clusters(domains, fps, labels=None, max_domains_per_fp: int = 300) -> tuple[np.ndarray, dict]:
    """Cluster id (0..k-1) for every row. A fingerprint seen on more than `max_domains_per_fp` domains is treated as
    generic (e.g. an empty template) and does not merge anything; rows without fingerprint stay with their domain."""
    d_codes, d_names = pd.factorize(pd.Series(list(domains)))
    n_dom = len(d_names)
    fp_series = pd.Series(list(fps), dtype=object)
    uf = _UnionFind(n_dom)
    generic = 0
    seen = pd.DataFrame({"d": d_codes, "fp": fp_series}).dropna().drop_duplicates()
    for _, g in seen.groupby("fp"):
        ds = g.d.to_numpy()
        if len(ds) < 2:
            continue
        if len(ds) > max_domains_per_fp:
            generic += 1
            continue
        for other in ds[1:]:
            uf.union(int(ds[0]), int(other))
    roots = np.array([uf.find(i) for i in range(n_dom)])
    _, dom_cluster = np.unique(roots, return_inverse=True)
    cluster = dom_cluster[d_codes]
    sizes = pd.Series(cluster).value_counts()
    dom_per_cluster = pd.Series(dom_cluster).value_counts()
    report = {"n_pages": int(len(cluster)), "n_domains": int(n_dom), "n_clusters": int(len(sizes)),
              "n_multi_domain_clusters": int((dom_per_cluster > 1).sum()),
              "domains_merged_away": int(n_dom - len(sizes)),
              "pages_without_fingerprint": int(fp_series.isna().sum()),
              "generic_fingerprints_skipped": int(generic),
              "largest_clusters_pages": [int(x) for x in sizes.head(5)],
              "largest_cluster_share": float(sizes.iloc[0] / len(cluster)) if len(cluster) else 0.0}
    if labels is not None:
        mixed = pd.DataFrame({"c": cluster, "y": np.asarray(labels).astype(int)}).groupby("c").y.nunique()
        report["mixed_label_clusters"] = int((mixed > 1).sum())          # label noise or a generic template
    if report["largest_cluster_share"] > 0.05:
        report["warning"] = "one cluster holds more than 5% of all pages; check for a generic fingerprint"
    return cluster, report


def cap_per_cluster(cluster, label, cap: int = 20, seed: int = 42) -> tuple[np.ndarray, dict]:
    """Keep at most `cap` pages per (cluster, label), chosen at random. Use on TRAINING rows only."""
    df = pd.DataFrame({"c": np.asarray(cluster), "y": np.asarray(label).astype(int)})
    rng = np.random.default_rng(seed)
    df["r"] = rng.random(len(df))
    rank = df.groupby(["c", "y"]).r.rank(method="first")
    keep = (rank <= cap).to_numpy()
    sizes = df.groupby(["c", "y"]).size()
    return keep, {"cap": cap, "pages_before": int(len(df)), "pages_kept": int(keep.sum()),
                  "pages_removed": int((~keep).sum()), "clusters_capped": int((sizes > cap).sum())}
