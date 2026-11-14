"""
Build data/dataset_own.csv  (own version of build_dataset.py; the old file is not touched).

    python -m aidev.pipeline_own.build_dataset_own
    python -m aidev.pipeline_own.build_dataset_own --neg-per-pos 1.5 --platform-cap 1000

Columns: url, label, group, source, kind, first_seen, hard_negative, synthetic_path
  label          1 = phishing / malicious, 0 = benign
  group          split key. Normally the registered domain, BUT for free-hosting platforms
                 (pages.dev, firebaseapp.com, github.io ...) every tenant host is its own group.
                 The old builder gave a whole platform ONE group, so at most 5 phishing URLs per
                 platform survived, although phishing on these platforms is common today.
  source         where the URL came from (phishtank, phishtank_old, phiusiil, feed, pages_*, tranco_*, ...)
  kind           phish | phish_on_service | feed_malware_like | feed_other | benign
                 phish_on_service = phishing reported on a URL shortener / QR-code service / big legitimate site
                 (google.com, bit.ly, github.com, adobe.com ... = a Tranco-listed domain with few hosts and many paths,
                 or any phishing on a Tranco top-5000 domain). The URL text says nothing about the phishing, so a
                 URL-only model cannot learn it; train_own.py keeps these rows out of training and out of the
                 headline test and only reports how they score.
                 (feeds_urls.txt mixes OpenPhish and URLhaus without a tag; feed_malware_like is a GUESS from
                  IP host / port / payload file name, so malware downloads can be reported separately)
  first_seen     UTC time the URL was first reported (only PhishTank has it: data/phishtank_dated.csv)
  hard_negative  1 = benign but looks suspicious: real login pages from pages.csv, Malaysian (.my) sites,
                 ID-style deep links
  synthetic_path 1 = the path was invented by the builder (benign homepages get a path so that
                 "has a path" cannot give the answer away)
All URLs are lower-cased, so letter case cannot separate the classes.
"""
from __future__ import annotations

import argparse
import random
from collections import Counter

import pandas as pd

from aidev.core.common import DATA, lines
from aidev.core.features import get_host, normalise, registered_domain
from aidev.pipeline.build_dataset import _PATH_TEMPLATES, _TEMPLATES, _fill, _has_path

MAX_PER_GROUP_POS = 5
MAX_PER_GROUP_NEG = 10

_DEFAULT_PLATFORMS = (
    "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "netlify.app", "vercel.app", "github.io",
    "gitlab.io", "blogspot.com", "weebly.com", "wixsite.com", "herokuapp.com", "glitch.me", "xsph.ru",
    "000webhostapp.com", "cloudfunctions.net", "appspot.com", "onrender.com", "repl.co", "myshopify.com",
    "sites.google.com", "notion.site", "godaddysites.com", "carrd.co", "webflow.io", "surge.sh",
    "trycloudflare.com", "duckdns.org", "ddns.net", "lima-city.de", "infinityfreeapp.com", "rf.gd",
    "r2.dev", "azurewebsites.net", "blob.core.windows.net", "amazonaws.com", "sharepoint.com", "square.site",
    "mystrikingly.com", "gitbook.io", "tiiny.site", "jimdosite.com",
    "weeblysite.com", "wixstudio.com", "dweb.link", "pantheonsite.io",     # found as "service" in the first real run
)
_PAYLOAD_EXT = (".sh", ".exe", ".bin", ".elf", ".apk", ".dll", ".msi", ".ps1", ".jar", ".arm", ".arm7", ".mips",
                ".mpsl", ".x86", ".spc", ".ppc", ".m68k", ".sh4", ".bat")


def _load_platforms() -> set[str]:
    plat = set(_DEFAULT_PLATFORMS)
    f = DATA.parent / "lists" / "shared_hosts.txt"          # the detector's own shared-host list, if it exists
    if f.exists():
        for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln = ln.strip().lower().lstrip("*.").lstrip(".")
            if ln and not ln.startswith("#"):
                plat.add(ln)
    return plat


PLATFORMS = _load_platforms()


def platform_of(host: str) -> str:
    parts = host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in PLATFORMS:
            return cand
    return ""


def _is_ip(text: str) -> bool:
    import re
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", text or ""))


def _host(url: str) -> str:
    try:
        h = get_host(url)
    except Exception:
        return ""
    return h[4:] if h.startswith("www.") else h


def group_of(url: str) -> str:
    host = _host(url)
    if host and platform_of(host):
        return host                                        # each tenant is its own group
    try:
        return registered_domain(url)
    except Exception:
        return ""


def _malware_like(url: str) -> bool:
    import re
    from urllib.parse import urlsplit
    p = urlsplit(normalise(url))
    host_is_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", p.hostname or ""))
    return host_is_ip or p.port is not None or (p.path or "").lower().endswith(_PAYLOAD_EXT) or "mozi" in (p.path or "").lower()


def _csv_col(path, col="url") -> list[str]:
    return [str(u).strip() for u in pd.read_csv(path)[col].dropna()]


def load_positives() -> pd.DataFrame:
    rows: list[dict] = []
    f = DATA / "phishtank_dated.csv"
    if f.exists():
        d = pd.read_csv(f)
        fs = d["first_seen"] if "first_seen" in d else pd.Series([None] * len(d))
        for u, t in zip(d["url"].astype(str), fs):
            rows.append({"url": u, "source": "phishtank", "kind": "phish", "first_seen": t})
    else:
        print("note: data/phishtank_dated.csv not found; there are no dated phishing URLs (no time split possible)")
    for f in sorted(DATA.glob("phishing_*.csv")):
        src = {"phishing_extra": "phishtank_old", "phishing_labeled": "phiusiil"}.get(f.stem, f.stem)
        rows += [{"url": u, "source": src, "kind": "phish", "first_seen": None} for u in _csv_col(f)]
    for u in lines(DATA / "feeds_urls.txt"):
        rows.append({"url": u, "source": "feed", "kind": "feed_malware_like" if _malware_like(u) else "feed_other",
                     "first_seen": None})
    df = pd.DataFrame(rows)
    df["url"] = df["url"].map(lambda u: normalise(u).lower())
    return df.drop_duplicates("url", keep="first").reset_index(drop=True)      # dated PhishTank rows come first


def main() -> None:
    ap = argparse.ArgumentParser(description="Build data/dataset_own.csv")
    ap.add_argument("--neg-per-pos", type=float, default=1.0, help="benign URLs per phishing URL (default 1.0)")
    ap.add_argument("--platform-cap", type=int, default=1000, help="max phishing URLs per free-hosting platform")
    ap.add_argument("--my-cap", type=int, default=3000, help="max Malaysian (.my) Tranco domains used as hard negatives")
    ap.add_argument("--service-min", type=int, default=200,
                    help="a registered domain with at least this many phishing URLs is looked at more closely (see docs)")
    ap.add_argument("--popular-top", type=int, default=5000,
                    help="phishing on a Tranco top-N domain is always a 'service' case, however few URLs there are")
    ap.add_argument("--service-cap", type=int, default=100, help="max phishing URLs kept per service domain (diagnostics only)")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    rng = random.Random(a.seed)

    # ---------------------------------------------------------------- positives
    pos_all = load_positives()
    if pos_all.empty:
        raise SystemExit("No phishing URLs found in data/.")
    def _reg(u):
        try:
            return registered_domain(u)
        except Exception:
            return ""
    pos_all["reg"] = pos_all["url"].map(_reg)
    tranco = lines(DATA / "tranco_top.txt")
    popular_top, popular_all = set(tranco[: a.popular_top]), set(tranco)
    pos_all["host"] = pos_all["url"].map(_host)
    stats = pos_all.groupby("reg").agg(urls=("url", "size"), hosts=("host", "nunique"))
    heavy = stats[(stats["urls"] >= a.service_min) & (stats.index != "")]
    # A heavy domain whose URLs sit on MANY different hosts is a hosting platform (every tenant has its own sub-domain,
    # so the URL text still carries information). One with few hosts and many paths (bit.ly, github.com ...) is a
    # service. A heavy domain that is not on the Tranco list is simply an attacker's own domain or IP: normal rows.
    auto_platforms = {d for d, r in heavy.iterrows() if not _is_ip(d) and r["hosts"] >= 30 and r["hosts"] / r["urls"] >= 0.2}
    PLATFORMS.update(auto_platforms)
    service = {d for d in heavy.index if d not in auto_platforms and not platform_of(d) and not _is_ip(d) and d in popular_all}
    service |= {d for d in stats.index if d in popular_top and not platform_of(d) and not _is_ip(d)}
    heavy_tbl = heavy.assign(
        decision=[("hosting platform (tenant = own group)" if d in auto_platforms or platform_of(d) else
                   "service (left out of training)" if d in service else "normal rows (attacker domain / IP)")
                  for d in heavy.index]).sort_values("urls", ascending=False)
    heavy_tbl.to_csv(DATA / "service_domains.csv")
    is_service = pos_all["reg"].isin(service)

    def cap_rows(frame, per_group_cap, use_platform_cap):
        order = list(frame.index)
        rng.shuffle(order)
        per_group: Counter = Counter()
        keep = []
        for i in order:
            u = frame.at[i, "url"]
            g = group_of(u)
            if not g or per_group[g] >= per_group_cap:
                continue
            if use_platform_cap:
                plat = platform_of(_host(u))
                if plat and per_platform[plat] >= a.platform_cap:
                    continue
                if plat:
                    per_platform[plat] += 1
            per_group[g] += 1
            keep.append(i)
        return frame.loc[keep]

    per_platform: Counter = Counter()
    normal = cap_rows(pos_all[~is_service], MAX_PER_GROUP_POS, True).copy()
    svc = cap_rows(pos_all[is_service], a.service_cap, False).copy()
    svc["kind"] = "phish_on_service"
    pos = pd.concat([normal, svc]).drop(columns=["reg"])
    pos["label"], pos["group"] = 1, [group_of(u) for u in pos["url"]]
    pos["hard_negative"], pos["synthetic_path"] = 0, 0
    phish_groups = set(pos.loc[pos["kind"] != "phish_on_service", "group"])   # service domains may also appear as benign
    p_path = float(pos["url"].map(_has_path).mean())

    # ---------------------------------------------------------------- negatives
    neg: list[dict] = []
    used_groups: set[str] = set()

    def add_neg(url, source, hard, synthetic):
        url = url.lower()
        neg.append({"url": url, "label": 0, "group": group_of(url), "source": source, "kind": "benign",
                    "first_seen": None, "hard_negative": int(hard), "synthetic_path": int(synthetic)})

    # (a) real benign pages crawled for model 2; the "login" ones are real hard negatives
    pf = DATA / "pages" / "pages.csv"
    if pf.exists():
        pg = pd.read_csv(pf, usecols=["url", "label", "source"])
        pg = pg[pg["label"] == 0].sample(frac=1, random_state=a.seed)
        cnt: Counter = Counter()
        for u, src in zip(pg["url"].astype(str), pg["source"].astype(str)):
            g = group_of(u)
            if not g or g in phish_groups or cnt[g] >= MAX_PER_GROUP_NEG:
                continue
            cnt[g] += 1
            add_neg(normalise(u), f"pages_{src}", "login" in src, False)
            used_groups.add(g)

    # (b) other real benign lists (PhiUSIIL homepages, your own browsing history file)
    for f in sorted(DATA.glob("benign_*.csv")):
        src = {"benign_extra": "own_history", "benign_labeled": "phiusiil_benign"}.get(f.stem, f.stem)
        cnt = Counter()
        urls = _csv_col(f)
        rng.shuffle(urls)
        for u in urls:
            g = group_of(u)
            if not g or g in phish_groups or cnt[g] >= MAX_PER_GROUP_NEG:
                continue
            cnt[g] += 1
            u = normalise(u)
            synthetic, hard = False, False
            if not _has_path(u) and rng.random() < p_path:
                tmpl = rng.choice(_PATH_TEMPLATES)
                u = u.rstrip("/") + _fill(tmpl, rng)
                synthetic, hard = True, ("{id}" in tmpl or "{uuid}" in tmpl)
            add_neg(u, src, hard, synthetic)
            used_groups.add(g)

    # (c) Tranco domains: all Malaysian ones (up to --my-cap) as hard negatives, then top and tail for the rest
    domains = [d for d in lines(DATA / "tranco_top.txt") if d not in phish_groups and d not in used_groups]
    my = [d for d in domains if d.endswith(".my")]
    rng.shuffle(my)
    my = my[: a.my_cap]
    my_set = set(my)
    others = [d for d in domains if d not in my_set]
    top, rest = others[:20000], others[20000:]
    rng.shuffle(top)
    rng.shuffle(rest)
    n_need = max(int(len(pos) * a.neg_per_pos) - len(neg), 0)
    chosen_my = my                                   # every .my domain (up to --my-cap) is kept, even if the quota is full
    n_other = max(n_need - len(chosen_my), 0)
    chosen = [(d, "tranco_my", True) for d in chosen_my]
    chosen += [(d, "tranco_synth", False) for d in top[: n_other // 2] + rest[: n_other - n_other // 2]]
    for d, src, hard in chosen:
        host = d if rng.random() < 0.7 else f"www.{d}"
        tmpl = rng.choice(_TEMPLATES)
        add_neg(f"https://{host}{_fill(tmpl, rng)}", src, hard or "{id}" in tmpl or "{uuid}" in tmpl, True)

    df = pd.concat([pos, pd.DataFrame(neg)], ignore_index=True)
    cols = ["url", "label", "group", "source", "kind", "first_seen", "hard_negative", "synthetic_path"]
    df = df[cols].drop_duplicates("url").sample(frac=1, random_state=a.seed).reset_index(drop=True)
    df["first_seen"] = pd.to_datetime(df["first_seen"], utc=True, errors="coerce").dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    df.to_csv(DATA / "dataset_own.csv", index=False)

    # ---------------------------------------------------------------- summary
    hp = df["url"].map(_has_path)
    print(f"dataset_own.csv: {len(df)} rows  (phishing {int(df.label.sum())}, benign {int((df.label == 0).sum())}, "
          f"{df.group.nunique()} groups)")
    print(f"share of URLs with a path: phishing {hp[df.label == 1].mean():.2f}, benign {hp[df.label == 0].mean():.2f}")
    print("\nrows per label / source / kind:")
    for (lab, src, kind), n in df.groupby(["label", "source", "kind"]).size().items():
        print(f"  label {lab}  {src:22s} {kind:18s} {n:>7d}")
    dated = df["first_seen"].notna().sum()
    print(f"\nphishing rows with a date: {dated} ({dated / max(int(df.label.sum()), 1):.0%})")
    print(f"benign hard negatives: {int(df.hard_negative.sum())}   (real, not synthetic: "
          f"{int(((df.hard_negative == 1) & (df.synthetic_path == 0) & (df.label == 0)).sum())})")
    sv = df[df["kind"] == "phish_on_service"]
    print(f"\nphishing domains with >= {a.service_min} URLs in the raw feeds (full table: data/service_domains.csv):")
    for dec in ("service (left out of training)", "hosting platform (tenant = own group)", "normal rows (attacker domain / IP)"):
        part = heavy_tbl[heavy_tbl["decision"] == dec]
        print(f"  {dec}: " + ", ".join(f"{d} {int(r.urls)}" for d, r in part.head(14).iterrows()) + (" ..." if len(part) > 14 else ""))
    if auto_platforms:
        print("  hosting platforms found automatically:", ", ".join(sorted(auto_platforms)))
    print(f"  kept {len(sv)} 'service' phishing rows for diagnostics only")
    if per_platform:
        print("phishing URLs per free-hosting platform:", ", ".join(f"{p} {n}" for p, n in per_platform.most_common(8)))


if __name__ == "__main__":
    main()
