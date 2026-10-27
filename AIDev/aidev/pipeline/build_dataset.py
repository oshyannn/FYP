"""
Build data/dataset.csv (columns: url, label, group).   python -m aidev.pipeline.build_dataset

label 1 = phishing/malicious, 0 = benign.  group = registered domain (used by train.py
to split by domain so near-duplicate URLs never land in both train and test).

Positives: data/feeds_urls.txt (+ optional data/phishing_extra.csv, column "url"),
           capped per registered domain so a few big campaigns do not dominate.
Negatives: Tranco domains with realistic paths (bare domains would teach the model
           "has a path => phishing"). The paths are SYNTHETIC; see ML_HANDOFF.md.
"""
from __future__ import annotations

import random
from urllib.parse import urlsplit

import pandas as pd

from aidev.core.common import DATA, lines
from aidev.core.features import normalise, registered_domain

SEED = 42
MAX_POS_PER_DOMAIN = 5
NEG_PER_POS = 1.0
MAX_BENIGN_PER_DOMAIN = 10

# Path templates seen on ordinary sites. {w}/{n} are filled randomly.
_WORDS = ["news", "about", "contact", "products", "blog", "help", "support", "login",
          "account", "search", "category", "shop", "careers", "privacy", "terms",
          "pricing", "docs", "download", "events", "store", "cart", "profile", "signin"]
_TEMPLATES = [
    "", "/", "/{w}", "/{w}/", "/{w}/{w}", "/{w}/{n}", "/{w}/{w}/{n}", "/{w}.html",
    "/{w}/{w}.php", "/{w}-{w}", "/en/{w}", "/en-us/{w}/{w}", "/{n}/{w}", "/p/{n}",
    "/{w}/{w}/{w}", "/index.html", "/wiki/{w}_{w}",
    # ID-style paths used by ordinary apps (documents, videos, files, product pages)
    "/d/{id}/edit", "/file/d/{id}/view", "/{w}/{id}", "/watch/{id}", "/p/{id}", "/{w}/{w}/{uuid}",
    "/document/d/{id}/edit", "/folders/{id}", "/item/{id}/{w}",
]


_PATH_TEMPLATES = [t for t in _TEMPLATES if t not in ("", "/")]


def _has_path(u: str) -> bool:
    return urlsplit(normalise(u)).path.rstrip("/") != ""


_ID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


def _rand_id(rng: random.Random) -> str:
    """Random document/video-style ID, e.g. Google Docs (44 chars) or YouTube (11 chars)."""
    return "".join(rng.choice(_ID_CHARS) for _ in range(rng.choice((11, 16, 22, 33, 44))))


def _rand_uuid(rng: random.Random) -> str:
    h = "".join(rng.choice("0123456789abcdef") for _ in range(32))
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def _fill(t: str, rng: random.Random) -> str:
    out = []
    i = 0
    while i < len(t):
        if t.startswith("{w}", i):
            out.append(rng.choice(_WORDS)); i += 3
        elif t.startswith("{id}", i):
            out.append(_rand_id(rng)); i += 4
        elif t.startswith("{uuid}", i):
            out.append(_rand_uuid(rng)); i += 6
        elif t.startswith("{n}", i):
            out.append(str(rng.randint(1, 99999))); i += 3
        else:
            out.append(t[i]); i += 1
    return "".join(out)


def main() -> None:
    rng = random.Random(SEED)

    # ---- positives
    pos = lines(DATA / "feeds_urls.txt")
    for f in sorted(DATA.glob("phishing_*.csv")):          # phishing_extra.csv, phishing_labeled.csv, ...
        pos += [str(u).strip().lower() for u in pd.read_csv(f)["url"].dropna()]
    pos = sorted(set(pos))
    if not pos:
        raise SystemExit("No phishing URLs. Run: python -m aidev.pipeline.feeds")

    per_domain: dict[str, int] = {}
    pos_rows = []
    rng.shuffle(pos)
    for u in pos:
        try:
            g = registered_domain(u)
        except Exception:
            continue
        if not g or per_domain.get(g, 0) >= MAX_POS_PER_DOMAIN:
            continue
        per_domain[g] = per_domain.get(g, 0) + 1
        pos_rows.append((normalise(u), 1, g))

    # Share of phishing URLs that carry a path. Bare-homepage benign URLs get a synthetic path with
    # the same probability, so "has a path" cannot be used to tell the classes apart.
    p_path = sum(_has_path(u) for u, _, _ in pos_rows) / max(len(pos_rows), 1)

    # ---- negatives
    phish_groups = set(per_domain)
    neg_rows = []
    used_groups: set[str] = set()

    # (a) real benign URLs, e.g. from export_history.py: kept as they are
    real_urls: list[str] = []
    for f in sorted(DATA.glob("benign_*.csv")):            # benign_extra.csv, benign_labeled.csv, ...
        real_urls += [str(u).strip() for u in pd.read_csv(f)["url"].dropna()]
    if real_urls:
        per_dom: dict[str, int] = {}
        for u in real_urls:
            try:
                g = registered_domain(u)
            except Exception:
                continue
            if not g or g in phish_groups or per_dom.get(g, 0) >= MAX_BENIGN_PER_DOMAIN:
                continue
            per_dom[g] = per_dom.get(g, 0) + 1
            url_n = normalise(u)
            if not _has_path(url_n) and rng.random() < p_path:
                url_n = url_n.rstrip("/") + _fill(rng.choice(_PATH_TEMPLATES), rng)
            neg_rows.append((url_n, 0, g))
            used_groups.add(g)
        print(f"real benign URLs used: {len(neg_rows)}")

    # (b) synthetic paths on Tranco domains: half from the very top, half from the whole list
    #     so that lesser-known legitimate sites are represented too
    domains = [d for d in lines(DATA / "tranco_top.txt") if d not in phish_groups and d not in used_groups]
    if not domains:
        raise SystemExit("No Tranco domains. Run: python -m aidev.pipeline.feeds")
    top, rest = domains[:20000], domains[20000:]
    rng.shuffle(top)
    rng.shuffle(rest)
    n_neg = max(int(len(pos_rows) * NEG_PER_POS) - len(neg_rows), 0)
    chosen = top[: n_neg // 2] + rest[: n_neg - n_neg // 2]
    if len(chosen) < n_neg:                      # short list: top up from whatever is left
        chosen += [d for d in top[n_neg // 2:] if d not in chosen][: n_neg - len(chosen)]
    for d in chosen:
        host = d if rng.random() < 0.7 else f"www.{d}"
        url = f"https://{host}{_fill(rng.choice(_TEMPLATES), rng)}"
        neg_rows.append((url, 0, registered_domain(url)))

    df = pd.DataFrame(pos_rows + neg_rows, columns=["url", "label", "group"])
    df = df.drop_duplicates("url").sample(frac=1, random_state=SEED).reset_index(drop=True)
    df.to_csv(DATA / "dataset.csv", index=False)
    hp = df["url"].map(_has_path)
    print(f"share of URLs with a path: phishing {hp[df.label == 1].mean():.2f}, benign {hp[df.label == 0].mean():.2f} (should be close)")
    print(f"dataset.csv: {len(df)} rows  (phishing {int(df.label.sum())}, benign {int((df.label == 0).sum())}, "
          f"{df.group.nunique()} domains)")


if __name__ == "__main__":
    main()
