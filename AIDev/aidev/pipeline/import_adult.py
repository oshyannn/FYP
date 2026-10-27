"""
Download a public adult-site domain list into data/adult_domains.txt (used by detector.py).

    python -m aidev.pipeline.import_adult                  # tries the built-in sources in order, merges what works
    python -m aidev.pipeline.import_adult --url URL        # a hosts-file or one-domain-per-line list of your choice
    python -m aidev.pipeline.import_adult --file FILE      # a list you already downloaded

Accepts hosts format ("0.0.0.0 example.com") and plain domain lists. Needs internet.
Add your own domains one per line to lists/adult_manual.txt (no download needed).
"""
from __future__ import annotations

import argparse
import re
import sys

import requests

from aidev.core.common import DATA

SOURCES = [
    "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
]
DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def parse(text: str) -> set[str]:
    out = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        parts = line.split()
        dom = parts[-1] if len(parts) > 1 else parts[0]
        if dom in {"localhost", "localhost.localdomain", "broadcasthost", "local", "0.0.0.0"}:
            continue
        if DOMAIN.match(dom):
            out.add(dom)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url")
    ap.add_argument("--file")
    a = ap.parse_args()

    domains: set[str] = set()
    if a.file:
        domains |= parse(open(a.file, encoding="utf-8", errors="ignore").read())
    for url in ([a.url] if a.url else ([] if a.file else SOURCES)):
        try:
            r = requests.get(url, timeout=60)
            if r.status_code != 200:
                print(f"  {url}: HTTP {r.status_code}")
                continue
            got = parse(r.text)
            print(f"  {url}: {len(got):,} domains")
            domains |= got
        except requests.RequestException as exc:
            print(f"  {url}: failed ({type(exc).__name__})")
    if not domains:
        sys.exit("No domains collected. Use --file with a list you downloaded yourself.")
    DATA.mkdir(exist_ok=True)
    (DATA / "adult_domains.txt").write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")
    print(f"wrote {len(domains):,} domains to data/adult_domains.txt")


if __name__ == "__main__":
    main()
