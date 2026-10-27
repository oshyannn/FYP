"""
Google Safe Browsing provider (Lookup API v4).

Why it exists: the Random Forest only sees the URL text, so a phishing page on a normal-looking
domain scores low. Safe Browsing is a reputation list (the same service Chrome uses for its red
"Dangerous site" page), so it catches pages the model cannot.

Setup: create an API key in Google Cloud Console (enable "Safe Browsing API"), then set
    GOOGLE_SAFE_BROWSING_API_KEY=<key>      (setx on Windows, then open a new terminal)
Without a key this module is simply inactive: check() reports "not configured" and the detector
ignores it.

Privacy: the Lookup API sends the full URL being checked to Google. Disclose this in the report.

The API key is never logged or put into an error message: requests includes the full request URL,
key included, in its exception text, so errors here are rebuilt from the status code only.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import requests

import common  # noqa: F401  (loads backend/.env into the environment)

log = logging.getLogger(__name__)

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
CLIENT = {"clientId": "urldetect-fyp", "clientVersion": "1.0.0"}
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]

_SCORES = {
    "SOCIAL_ENGINEERING": 100.0,            # phishing
    "MALWARE": 100.0,
    "UNWANTED_SOFTWARE": 85.0,
    "POTENTIALLY_HARMFUL_APPLICATION": 85.0,
}


def is_configured() -> bool:
    return bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"))


@dataclass(frozen=True)
class SafeBrowsingVerdict:
    """
    `succeeded` False means we learned nothing (no key, network error, quota, bad response) and the
    caller must not treat it as evidence of safety. `found` False with `succeeded` True means Google
    has no record: weak evidence of safety only, since new pages take time to be listed.
    """

    succeeded: bool
    found: bool = False
    threat_type: str | None = None
    configured: bool = True
    error: str | None = None

    @property
    def risk_contribution(self) -> float | None:
        if not self.succeeded or not self.found:
            return None
        return _SCORES.get(self.threat_type or "", 85.0)


def check(url: str, api_key: str | None = None, timeout: float = 3.0) -> SafeBrowsingVerdict:
    key = api_key or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return SafeBrowsingVerdict(succeeded=False, configured=False, error="no API key set")

    body = {
        "client": CLIENT,
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(ENDPOINT, params={"key": key}, json=body, timeout=timeout)
    except requests.RequestException as exc:
        return SafeBrowsingVerdict(succeeded=False, error=f"request failed ({type(exc).__name__})")

    if response.status_code != 200:
        return SafeBrowsingVerdict(succeeded=False, error=f"HTTP {response.status_code}")

    try:
        data = response.json()
    except ValueError:
        return SafeBrowsingVerdict(succeeded=False, error="undecodable response")
    if not isinstance(data, dict):
        return SafeBrowsingVerdict(succeeded=False, error="unexpected response shape")

    matches = data.get("matches")
    if not matches:                       # documented: no match -> empty object {}
        return SafeBrowsingVerdict(succeeded=True, found=False)

    types = [m.get("threatType") for m in matches if isinstance(m, dict)]
    worst = max(types, key=lambda t: _SCORES.get(t or "", 85.0), default=None)
    return SafeBrowsingVerdict(succeeded=True, found=True, threat_type=worst)
