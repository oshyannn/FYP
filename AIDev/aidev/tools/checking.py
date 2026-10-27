"""
Downloads PhishTank's full verified-phish database and lists every stored URL
whose domain matches, so you can see exactly what is and isn't in there —
instead of guessing from single checkurl lookups.

With an API key you get a higher download rate limit, so this is safe to run
once while you're debugging.
"""

import json
import os

import requests

API_KEY = os.getenv("PHISHTANK_API_KEY", "")
DOMAIN_TO_CHECK = "services-consignes-instructions.com"

FEED_URL = f"http://data.phishtank.com/data/{API_KEY}/online-valid.json"

print("Downloading PhishTank verified-phish feed (this can take a moment)...")
response = requests.get(
    FEED_URL,
    headers={"User-Agent": "phishtank/urldetect-fyp (+youraccount@gmail.com)"},
    timeout=60,
)
response.raise_for_status()

records = response.json()
print(f"Total verified entries in feed: {len(records)}\n")

matches = [r for r in records if DOMAIN_TO_CHECK in r.get("url", "")]

if not matches:
    print(f"No records at all contain '{DOMAIN_TO_CHECK}'.")
else:
    print(f"Found {len(matches)} record(s) for that domain:\n")
    for r in matches:
        print("phish_id     :", r.get("phish_id"))
        print("url          :", r.get("url"))
        print("verified     :", r.get("verified"))
        print("verified_at  :", r.get("verification_time"))
        print("online       :", r.get("online"))
        print("target       :", r.get("target"))
        print("-" * 60)