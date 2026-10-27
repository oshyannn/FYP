"""
PhishTank provider.

Fixes over the original implementation:

  * Uses the documented endpoint over HTTPS.
  * Sends a real descriptive User-Agent (PhishTank throttles generic ones).
  * Base64-encodes the URL, which is what the docs recommend and what avoids
    special-character mangling.
  * Tries several URL variants, because PhishTank matches the full URL exactly
    and will miss on a scheme or trailing-slash difference alone.
  * Distinguishes "not in the database" from "the lookup failed". These are not
    the same thing, and collapsing them into risk_score=0 is what made a
    confirmed phishing site look clean.

Registration for new API keys has been closed since 2020. Without a key you get
a lower rate limit but the API still answers, so app_key is optional here.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import requests

from common import is_shared

log = logging.getLogger(__name__)

ENDPOINT = "https://checkurl.phishtank.com/checkurl/"

# Replace with your real project identifier and a contact address. PhishTank
# asks for this so they can reach you before they block you.
USER_AGENT = "phishtank/urldetect-fyp (+ongsy-wm23@student.tarc.edu.my)"


@dataclass(frozen=True)
class PhishTankVerdict:
    """
    Outcome of a PhishTank lookup.

    `succeeded` False means we learned nothing — network error, rate limit,
    malformed response. The caller must NOT treat that as evidence of safety.

    `match_scope` distinguishes what actually matched:
      - "exact"  : the specific path the user visited is a verified record
      - "domain" : the exact path was never reported, but the same domain has
                   a verified phishing record on a different path (root,
                   /index.php, etc). Phishing kits routinely spray many paths
                   under one domain, and PhishTank only has the paths someone
                   happened to report — so a domain-level hit is still strong
                   evidence, just not as strong as an exact one.
      - None     : nothing on this domain is in the database at all.
    """

    succeeded: bool
    found: bool = False
    verified: bool = False
    valid: bool = False
    match_scope: str | None = None      # "exact" | "domain" | None
    matched_url: str | None = None
    phish_id: str | None = None
    detail_url: str | None = None
    error: str | None = None

    @property
    def risk_contribution(self) -> float | None:
        """
        0-100 score, or None when this provider has no opinion.

        None is deliberate for a true miss. `not in PhishTank` is weak evidence
        of safety: the database is community-verified and lags new campaigns
        by hours to days, so most fresh phishing pages are simply absent.
        """
        if not self.succeeded or not self.found:
            return None

        if self.verified and not self.valid:
            return None          # community voted "not phishing" -> no evidence
        if not self.verified:
            # submitted but not yet voted on: only trust an exact-path match
            return 40.0 if self.match_scope == "exact" else None

        if self.match_scope == "exact":
            return 100.0
        if self.match_scope == "domain":
            # Same domain confirmed malicious; this exact path just hasn't
            # been individually reported. Treat as high risk, not a clean bill.
            return 85.0
        return 0.0


def _url_variants(url: str) -> list[tuple[str, str]]:
    """
    Generate the forms PhishTank might have stored, most specific first.

    Returns (variant_url, scope) pairs. scope is "exact" for anything that
    preserves the original path, "domain" for the bare-origin fallback (root
    path only) — a hit there means the domain is confirmed malicious even
    though this specific path was never individually reported.

    PhishTank does exact string matching, so 'https://x.com/a.php' and
    'http://x.com/a.php' are different records to it, hence the scheme and
    www/non-www variants.
    """
    parsed = urlsplit(url)
    if not parsed.netloc:
        return [(url, "exact")]

    host = parsed.netloc
    alt_host = host[4:] if host.startswith("www.") else f"www.{host}"
    is_already_root = parsed.path in ("", "/") and not parsed.query

    variants: list[tuple[str, str]] = []
    for scheme in ("https", "http"):
        for netloc in (host, alt_host):
            variants.append(
                (urlunsplit((scheme, netloc, parsed.path, parsed.query, "")), "exact")
            )
            if parsed.query:
                variants.append(
                    (urlunsplit((scheme, netloc, parsed.path, "", "")), "exact")
                )
            if not is_already_root and not is_shared(parsed.hostname or ""):
                variants.append(
                    (urlunsplit((scheme, netloc, "/", "", "")), "domain")
                )

    # de-duplicate on URL, preserve order and first-seen scope
    seen: set[str] = set()
    ordered: list[tuple[str, str]] = []
    for v, scope in variants:
        if v and v not in seen:
            seen.add(v)
            ordered.append((v, scope))
    return ordered


def _truthy(value) -> bool:
    """
    PhishTank's checkurl response has used both conventions over the years:
    the documented "y"/"n" strings, and (as observed live, 2026) native JSON
    booleans. Accept either so a format change doesn't silently zero out
    every verified record again.
    """
    return value is True or value == "y"


def _lookup_one(url: str, scope: str, api_key: str | None, timeout: float) -> PhishTankVerdict:
    payload = {
        "url": base64.b64encode(url.encode()).decode(),
        "format": "json",
    }
    if api_key:
        payload["app_key"] = api_key

    try:
        response = requests.post(
            ENDPOINT,
            data=payload,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        return PhishTankVerdict(succeeded=False, error=f"request failed: {exc}")

    # A rate-limit page comes back as HTTP 200 with HTML. .json() explodes on it,
    # which the original code never caught.
    content_type = response.headers.get("Content-Type", "")
    if "json" not in content_type.lower():
        return PhishTankVerdict(
            succeeded=False,
            error=f"non-JSON response ({content_type or 'no content-type'}) "
                  f"— usually rate limiting",
        )

    try:
        body = response.json()
    except ValueError as exc:
        return PhishTankVerdict(succeeded=False, error=f"undecodable JSON: {exc}")

    if body.get("meta", {}).get("status") == "error":
        return PhishTankVerdict(
            succeeded=False,
            error=str(body.get("errortext", "PhishTank returned an error")),
        )

    results = body.get("results")
    if not isinstance(results, dict):
        return PhishTankVerdict(succeeded=False, error="missing 'results' object")

    found = results.get("in_database") is True
    return PhishTankVerdict(
        succeeded=True,
        found=found,
        verified=_truthy(results.get("verified")),
        valid=_truthy(results.get("valid")),
        match_scope=scope if found else None,
        matched_url=url,
        phish_id=results.get("phish_id"),
        detail_url=results.get("phish_detail_page"),
    )


def check(url: str, api_key: str | None = None, timeout: float = 5.0,
          max_variants: int = 8) -> PhishTankVerdict:
    """
    Look a URL up in PhishTank, trying exact-path variants first and the bare
    domain last. An exact hit returns immediately. A domain-level hit is kept
    as a fallback but the search keeps going in case a later variant is an
    exact match after all — exact evidence should always win when both exist.

    max_variants is capped low on purpose: each variant is a separate HTTP
    request against a rate-limited free API, and you are calling this on every
    page navigation.
    """
    best_domain_hit: PhishTankVerdict | None = None
    last_failure: PhishTankVerdict | None = None

    for variant_url, scope in _url_variants(url)[:max_variants]:
        verdict = _lookup_one(variant_url, scope, api_key, timeout)
        log.debug("PhishTank %s [%s] -> succeeded=%s found=%s",
                  variant_url, scope, verdict.succeeded, verdict.found)

        if not verdict.succeeded:
            last_failure = verdict
            continue

        if verdict.found:
            if scope == "exact":
                return verdict                 # strongest possible evidence, stop here
            if best_domain_hit is None:
                best_domain_hit = verdict       # remember it, keep looking for "exact"

    if best_domain_hit is not None:
        return best_domain_hit

    # Every variant answered cleanly and none matched at all.
    if last_failure is None:
        return PhishTankVerdict(succeeded=True, found=False)

    # At least one lookup errored, so a clean "not found" elsewhere is not
    # fully trustworthy — surface the failure rather than silently saying safe.
    return last_failure