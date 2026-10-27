"""
Domain registration lookup via RDAP (the successor of WHOIS), used ONLY for look-alike hits.

Gives two facts when the registry exposes them:
  * registration date -> a look-alike registered 5 days ago is far more suspicious than one that is 10 years old
  * registrant organisation -> if both domains show the SAME organisation, it is the same owner (defensive
    registration), not an imitation.

Honest limits:
  * Since GDPR most registrants are redacted, so "same owner" can often not be decided (-> unknown, never "safe").
  * Some country registries (e.g. .my) have no RDAP entry in the IANA bootstrap: result is "unsupported".
  * A criminal can also register a domain long before using it; age is evidence, not proof.
  * Network call (timeout 3 s). Results are cached; failures are never treated as evidence.
  * Privacy: the domain name (not the full URL) is sent to the registry.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

from common import DATA

log = logging.getLogger(__name__)
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_FILE = DATA / "rdap_dns.json"
_REDACTED = ("redact", "privacy", "withheld", "not disclosed", "data protected", "proxy", "whoisguard", "n/a")


@dataclass(frozen=True)
class RdapInfo:
    succeeded: bool
    created: datetime | None = None
    registrant: str | None = None
    error: str | None = None

    @property
    def age_days(self) -> int | None:
        if self.created is None:
            return None
        return max(0, (datetime.now(timezone.utc) - self.created).days)


def _bootstrap() -> dict[str, str]:
    """TLD -> RDAP base URL. Cached on disk for 7 days; an old copy is better than none."""
    try:
        fresh = BOOTSTRAP_FILE.exists() and time.time() - BOOTSTRAP_FILE.stat().st_mtime < 7 * 86400
        if not fresh:
            r = requests.get(BOOTSTRAP_URL, timeout=5)
            if r.status_code == 200:
                BOOTSTRAP_FILE.write_text(r.text, encoding="utf-8")
        data = json.loads(BOOTSTRAP_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for tlds, urls in data.get("services", []):
        base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
        for t in tlds:
            if base:
                out[t.lower()] = base if base.endswith("/") else base + "/"
    return out


def parse(data: dict) -> RdapInfo:
    """Pure function (testable offline): RDAP domain JSON -> RdapInfo."""
    created = None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration":
            try:
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
            except (KeyError, ValueError):
                pass
    registrant = None
    for ent in data.get("entities", []):
        if "registrant" in ent.get("roles", []):
            card = ent.get("vcardArray") or []
            for item in (card[1] if len(card) > 1 else []):
                if item and item[0] in ("org", "fn") and len(item) > 3 and isinstance(item[3], str):
                    val = item[3].strip()
                    if val and not any(w in val.lower() for w in _REDACTED):
                        registrant = " ".join(val.lower().split())
                        break
    return RdapInfo(succeeded=True, created=created, registrant=registrant)


_cache: dict[str, tuple[float, RdapInfo]] = {}


def lookup(registered_domain: str, timeout: float = 3.0) -> RdapInfo:
    now = time.time()
    hit = _cache.get(registered_domain)
    if hit and hit[0] > now:
        return hit[1]
    info = _fetch(registered_domain, timeout)
    _cache[registered_domain] = (now + (86400 if info.succeeded else 300), info)
    return info


def _fetch(domain: str, timeout: float) -> RdapInfo:
    base = _bootstrap().get(domain.rsplit(".", 1)[-1])
    if not base:
        return RdapInfo(False, error="no RDAP service for this domain ending")
    try:
        r = requests.get(f"{base}domain/{domain}", timeout=timeout, headers={"Accept": "application/rdap+json"})
    except requests.RequestException as exc:
        return RdapInfo(False, error=f"request failed ({type(exc).__name__})")
    if r.status_code != 200:
        return RdapInfo(False, error=f"HTTP {r.status_code}")
    try:
        return parse(r.json())
    except ValueError:
        return RdapInfo(False, error="undecodable response")
