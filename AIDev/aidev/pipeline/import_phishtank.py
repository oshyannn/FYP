"""
Build data/phishing_extra.csv from the PhishTank verified-phish feed.

    python import_phishtank.py                  # downloads the feed (needs PHISHTANK_API_KEY, like scripts/checking.py)
    python import_phishtank.py online-valid.json  # or use a feed file you already saved

build_dataset.py reads phishing_extra.csv automatically. Run build_dataset.py and train.py after.
"""
from __future__ import annotations

import bz2
import io
import json
import os
import sys

import pandas as pd
import requests

from common import DATA

USER_AGENT = "phishtank/urldetect-fyp (+your.email@student.tarc.edu.my)"


FORMATS = ("online-valid.json.bz2", "online-valid.json", "online-valid.csv.bz2", "online-valid.csv")


def _parse(name: str, content: bytes) -> list[dict]:
    if name.endswith(".bz2"):
        content = bz2.decompress(content)
    if ".json" in name:
        return json.loads(content.decode("utf-8"))
    return pd.read_csv(io.BytesIO(content)).to_dict("records")     # CSV: columns include url, verified


def load_records() -> list[dict]:
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as f:
            return json.load(f)
    key = os.getenv("PHISHTANK_API_KEY", "")
    if not key:
        raise SystemExit("PHISHTANK_API_KEY is not set in this terminal. Set it, reopen the terminal, "
                         "or pass a saved feed file as an argument.")
    errors = []
    for name in FORMATS:                      # PhishTank sometimes breaks one format; try the others
        print(f"Downloading {name} ...")
        try:
            r = requests.get(f"http://data.phishtank.com/data/{key}/{name}",
                             headers={"User-Agent": USER_AGENT}, timeout=120)
            r.raise_for_status()
            return _parse(name, r.content)
        except Exception as exc:
            errors.append(f"{name}: {str(exc).split('?')[0]}")
            print("  failed:", errors[-1])
    raise SystemExit("All PhishTank formats failed:\n  " + "\n  ".join(errors) +
                     "\nThe feed is regenerated hourly on the hour: wait a few minutes and retry, "
                     "or skip this step (OpenPhish + URLhaus are enough to train).")


def main() -> None:
    records = load_records()
    urls = sorted({str(r["url"]).strip() for r in records
                   if r.get("url") and str(r.get("verified", "yes")).lower() in ("true", "yes", "y", "1")})
    DATA.mkdir(exist_ok=True)
    pd.DataFrame({"url": urls}).to_csv(DATA / "phishing_extra.csv", index=False)
    print(f"phishing_extra.csv: {len(urls)} verified URLs")


if __name__ == "__main__":
    main()
