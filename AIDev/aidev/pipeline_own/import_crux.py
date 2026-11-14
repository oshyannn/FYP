"""
Real benign hard negatives from Google's Chrome UX Report (CrUX) top-sites list.
The list is a dataset made by others; the code here is your own.

    python -m aidev.pipeline_own.import_crux                          # downloads once, keeps the file in data/raw/
    python -m aidev.pipeline_own.import_crux C:\\path\\current.csv.gz    # or use a file you downloaded yourself

Writes  data/benign_crux_tenants.csv   popular real sites that live on free-hosting platforms (github.io, weebly.com ...)
        data/benign_crux_my.csv        popular Malaysian (.my) sites
Why: the data has phishing on hosting platforms but no benign sites there, so a model could learn "lives on weebly = bad".
The .my sites are the local hard negatives. build_dataset_own.py picks both files up automatically (run it afterwards).
Source: https://github.com/zakird/crux-top-lists  (monthly top 1M origins, columns origin,rank). Check the licence and cite it
in the report. If the download fails, download the file yourself and pass its path as the argument.
"""
from __future__ import annotations

import argparse
import random
import time
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import requests

from aidev.core.common import DATA
from aidev.pipeline_own.build_dataset_own import PLATFORMS, _host, platform_of

URL = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz"
RAW = DATA / "raw" / "crux_top_current.csv.gz"


def load_origins(path: str | None) -> list[str]:
    if path:
        p = Path(path)
    else:
        p = RAW
        if not p.exists() or time.time() - p.stat().st_mtime > 30 * 86400:
            print(f"downloading {URL} (once) ...")
            try:
                r = requests.get(URL, timeout=300)
                r.raise_for_status()
            except Exception as exc:
                raise SystemExit(f"download failed ({exc}).\nDownload the CrUX top list yourself "
                                 "(github.com/zakird/crux-top-lists) and pass the file path as the argument.")
            RAW.parent.mkdir(parents=True, exist_ok=True)
            RAW.write_bytes(r.content)
    df = pd.read_csv(p)
    col = "origin" if "origin" in df.columns else df.columns[0]
    return df[col].dropna().astype(str).tolist()


def main() -> None:
    ap = argparse.ArgumentParser(description="CrUX top sites -> benign hard negatives")
    ap.add_argument("file", nargs="?", help="a CrUX top-list csv/csv.gz you already have")
    ap.add_argument("--cap", type=int, default=800, help="max benign sites per hosting platform (default 800)")
    ap.add_argument("--my-cap", type=int, default=4000, help="max .my sites (default 4000)")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    rng = random.Random(a.seed)

    sd = DATA / "service_domains.csv"                     # hosting platforms the dataset builder found automatically
    if sd.exists():
        t = pd.read_csv(sd, index_col=0)
        PLATFORMS.update(t.index[t["decision"].astype(str).str.startswith("hosting platform")])

    origins = load_origins(a.file)
    print(f"{len(origins)} origins read")
    per_platform: dict[str, list[str]] = {}
    my: list[str] = []
    for o in origins:
        host = _host(o)
        if not host:
            continue
        plat = platform_of(host)
        if plat and host != plat:                          # a tenant, not the platform's own site
            per_platform.setdefault(plat, []).append(f"{urlsplit(o).scheme}://{host}")
        elif host.endswith(".my"):
            my.append(f"{urlsplit(o).scheme}://{host}")
    tenants = []
    for plat, urls in per_platform.items():
        rng.shuffle(urls)
        tenants += urls[: a.cap]
    rng.shuffle(my)
    my = my[: a.my_cap]
    pd.DataFrame({"url": [u.lower() for u in tenants]}).to_csv(DATA / "benign_crux_tenants.csv", index=False)
    pd.DataFrame({"url": [u.lower() for u in my]}).to_csv(DATA / "benign_crux_my.csv", index=False)
    top = sorted(per_platform.items(), key=lambda kv: -len(kv[1]))[:10]
    print(f"benign_crux_tenants.csv: {len(tenants)} sites on {len(per_platform)} platforms; largest: "
          + ", ".join(f"{p} {min(len(u), a.cap)}" for p, u in top))
    print(f"benign_crux_my.csv: {len(my)} Malaysian sites")
    print("next: python -m aidev.pipeline_own.build_dataset_own")


if __name__ == "__main__":
    main()
