"""
Download the PhishTank verified-phish feed ONCE, keep the raw file, and write data/phishtank_dated.csv
with the date each URL was submitted (first_seen). Put this file in AIDev/aidev/pipeline_own/.
Run from the AIDev folder (venv active):

    python -m aidev.pipeline_own.import_phishtank_dated                # reuse a saved file younger than 24 h, else download ONCE
    python -m aidev.pipeline_own.import_phishtank_dated --refresh      # force a new download (PhishTank limits repeats)
    python -m aidev.pipeline_own.import_phishtank_dated C:\\path\\online-valid.json   # use a file you already have (.json or .bz2)

Why it is different from import_phishtank.py:
  * It keeps submission_time, so the data can be split by date.
  * It saves the raw feed to data/raw/, so you never need to download it twice.
  * It asks for ONE format; if PhishTank says "too many requests" (HTTP 429 / 509) it stops at once instead of
    trying three more formats (every try counts against the limit).
  * It never prints your API key (the key is part of the download address, so error messages would show it).
It does not touch data/phishing_extra.csv, so nothing that works today changes.
The key is read from the environment or from AIDev/.env (PHISHTANK_API_KEY).
"""
from __future__ import annotations

import argparse
import bz2
import io
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

from aidev.core.common import DATA                       # importing this also loads AIDev/.env
from aidev.core.features import registered_domain

RAW_DIR = DATA / "raw"
OUT = DATA / "phishtank_dated.csv"
USER_AGENT = "phishtank/urldetect-fyp (+your.email@student.tarc.edu.my)"
FORMATS = ("online-valid.json.bz2", "online-valid.json")
RATE_LIMIT = (429, 509)
MAX_AGE_H = 24


def _parse(name: str, content: bytes) -> list[dict]:
    if name.endswith(".bz2"):
        content = bz2.decompress(content)
    if ".json" in name:
        return json.loads(content.decode("utf-8"))
    return pd.read_csv(io.BytesIO(content)).to_dict("records")


def _hide(text: str, key: str) -> str:
    return text.replace(key, "***") if key else text


def _saved() -> list[Path]:
    return sorted(RAW_DIR.glob("phishtank_online-valid_*.json"))


def _read_saved(p: Path) -> list[dict]:
    return json.loads(p.read_text(encoding="utf-8"))


def load_records(file_arg: str | None, refresh: bool) -> list[dict]:
    if file_arg:
        p = Path(file_arg)
        print(f"Using the file you gave: {p}")
        return _parse(p.name, p.read_bytes())

    saved = _saved()
    if saved and not refresh and (time.time() - saved[-1].stat().st_mtime) < MAX_AGE_H * 3600:
        print(f"Using the saved feed {saved[-1].name} (younger than {MAX_AGE_H} h, no download).")
        return _read_saved(saved[-1])

    key = os.getenv("PHISHTANK_API_KEY", "").strip()

    def fallback(reason: str) -> list[dict]:
        if saved:
            print(f"{reason}\nUsing the older saved feed {saved[-1].name} instead.")
            return _read_saved(saved[-1])
        raise SystemExit(f"{reason}\nNo saved feed to fall back on. Wait a while and run again, "
                         "or pass a feed file you already have as an argument.")

    if not key:
        return fallback("PHISHTANK_API_KEY is not set (environment or AIDev/.env).")

    errors = []
    for name in FORMATS:
        print(f"Downloading {name} ... (one request)")
        try:
            r = requests.get(f"http://data.phishtank.com/data/{key}/{name}",
                             headers={"User-Agent": USER_AGENT}, timeout=180)
            if r.status_code in RATE_LIMIT:
                return fallback(f"PhishTank is limiting you (HTTP {r.status_code}). Stop and wait; "
                                "the feed refreshes on the hour, and repeated tries make the wait longer.")
            r.raise_for_status()
            records = _parse(name, r.content)
            RAW_DIR.mkdir(parents=True, exist_ok=True)
            out = RAW_DIR / f"phishtank_online-valid_{datetime.now(timezone.utc):%Y%m%d-%H%M}.json"
            out.write_text(json.dumps(records), encoding="utf-8")
            print(f"Saved the raw feed to {out}  (reuse it; do not download again today)")
            return records
        except Exception as exc:
            errors.append(f"{name}: {_hide(str(exc), key)}")
            print("  failed:", errors[-1])
    return fallback("All downloads failed:\n  " + "\n  ".join(errors))


def _group(url: str) -> str:
    try:
        return registered_domain(url)
    except Exception:
        return ""


def build_table(records: list[dict]) -> pd.DataFrame:
    rows = []
    for r in records:
        url = str(r.get("url") or "").strip()
        if not url or str(r.get("verified", "yes")).lower() not in ("yes", "true", "y", "1"):
            continue
        rows.append({"url": url, "first_seen": r.get("submission_time"), "verified_at": r.get("verification_time"),
                     "online": r.get("online"), "target": r.get("target"), "phish_id": r.get("phish_id")})
    df = pd.DataFrame(rows, columns=["url", "first_seen", "verified_at", "online", "target", "phish_id"])
    for c in ("first_seen", "verified_at"):
        df[c] = pd.to_datetime(df[c], utc=True, errors="coerce")
    df = df.drop_duplicates("url").sort_values("first_seen").reset_index(drop=True)
    df["source"] = "phishtank"
    df["group"] = df["url"].map(_group)
    return df


def main() -> int:
    ap = argparse.ArgumentParser(description="PhishTank verified feed -> data/phishtank_dated.csv (with dates)")
    ap.add_argument("file", nargs="?", help="a PhishTank feed you already saved (.json or .bz2)")
    ap.add_argument("--refresh", action="store_true", help="download again even if a recent file is saved")
    a = ap.parse_args()

    df = build_table(load_records(a.file, a.refresh))
    if df.empty:
        print("No verified URLs found in the feed.")
        return 1
    out = df.copy()
    for c in ("first_seen", "verified_at"):
        out[c] = out[c].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    DATA.mkdir(exist_ok=True)
    out.to_csv(OUT, index=False)

    dated = df.dropna(subset=["first_seen"])
    print(f"\n{OUT.name}: {len(df)} verified URLs, {len(dated)} with a usable date, {df.group.nunique()} registered domains")
    if dated.empty:
        print("No dates could be read. Send me the first 3 records of the raw file.")
        return 1
    print(f"date range: {dated.first_seen.min():%Y-%m-%d} to {dated.first_seen.max():%Y-%m-%d}")
    print("URLs per month (newest 8):")
    for m, n in dated.groupby(dated.first_seen.dt.strftime("%Y-%m")).size().tail(8).items():
        print(f"  {m}  {n}")
    cut = dated.first_seen.quantile(0.8)
    test = dated[dated.first_seen > cut]
    print(f"an 80/20 date split would cut at {cut:%Y-%m-%d}: test = {len(test)} URLs from {test.group.nunique()} domains")
    print("most frequent registered domains (free hosting shows up here):")
    for g, n in df.group.value_counts().head(10).items():
        print(f"  {g or '(none)':35s} {n}")
    tg = df.target.dropna().astype(str).value_counts().head(5)
    if len(tg):
        print("most imitated targets:", ", ".join(f"{t} ({n})" for t, n in tg.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
