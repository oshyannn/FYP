"""
Download training/lookup data into data/. Run about daily:  python feeds.py

  data/tranco_top.txt   top domains (benign source), one per line
  data/feeds_urls.txt   OpenPhish + URLhaus URLs (phishing/malware source), one per line

Needs internet. Each source is fetched independently; one failing does not stop the others.
"""
from __future__ import annotations

import io
import sys
import zipfile

import requests

from common import DATA

UA = {"User-Agent": "urldetect-fyp/1.0"}
TIMEOUT = 60
TRANCO_LIMIT = 300_000


def _get(url: str) -> requests.Response:
    r = requests.get(url, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return r


def fetch_tranco() -> int:
    r = _get("https://tranco-list.eu/top-1m.csv.zip")
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        raw = z.read(z.namelist()[0]).decode("utf-8", "ignore").splitlines()
    domains = [ln.split(",", 1)[1].strip().lower() for ln in raw[:TRANCO_LIMIT] if "," in ln]
    (DATA / "tranco_top.txt").write_text("\n".join(domains), encoding="utf-8")
    return len(domains)


def fetch_urls() -> int:
    urls: set[str] = set()
    for name, src in (
        ("OpenPhish", "https://openphish.com/feed.txt"),
        ("URLhaus", "https://urlhaus.abuse.ch/downloads/text_online/"),
    ):
        try:
            for ln in _get(src).text.splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("#") and ln.lower().startswith("http"):
                    urls.add(ln)
            print(f"  {name}: ok")
        except Exception as exc:
            print(f"  {name}: FAILED ({exc})")
    if urls:
        (DATA / "feeds_urls.txt").write_text("\n".join(sorted(urls)), encoding="utf-8")
    return len(urls)


def main() -> int:
    DATA.mkdir(exist_ok=True)
    ok = True
    try:
        print(f"Tranco: {fetch_tranco()} domains")
    except Exception as exc:
        ok = False
        print(f"Tranco FAILED: {exc}")
    n = fetch_urls()
    print(f"Feed URLs: {n}")
    ok = ok and n > 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
