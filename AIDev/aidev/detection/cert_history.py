"""
Certificate history of a domain, from the public Certificate Transparency logs (via crt.sh), plus the organisation named in the
certificate the site shows right now.

    from aidev.detection.cert_history import lookup
    c = lookup("sinchew.com.my")     # CertInfo: first_seen, n_certs, issuers, org

Why it is evidence that does not depend on any blacklist:
  * Every publicly trusted HTTPS certificate is written to the CT logs. A domain whose first certificate was issued years ago and
    that has been renewed many times has existed for years. A brand-new domain has no history and cannot fake one.
  * A certificate that names an organisation (OV / EV) means the certificate authority checked who is behind the site. Free
    certificates used by most phishing sites (DV) carry no organisation.
Honest limits: the first certificate is a LOWER BOUND of the domain's age (the domain may be older). An organisation name proves a
company bought the certificate, not that it is the company the page claims to be. crt.sh is a free service that is sometimes slow
or busy (timeout 6 s): a failed lookup is "no opinion", never evidence. Only the domain name is sent, never the full URL.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

CRT_URL = "https://crt.sh/"


@dataclass(frozen=True)
class CertInfo:
    succeeded: bool
    first_seen: datetime | None = None
    n_certs: int = 0
    issuers: tuple[str, ...] = field(default_factory=tuple)
    org: str | None = None            # organisation in the certificate the site shows now (OV / EV), None for DV
    error: str | None = None

    @property
    def days(self) -> int | None:
        return None if self.first_seen is None else max(0, (datetime.now(timezone.utc) - self.first_seen).days)


def _dt(text: str) -> datetime | None:
    try:
        d = datetime.fromisoformat((text or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def parse_crt(text: str) -> tuple[datetime | None, int, tuple[str, ...]]:
    """Pure function (testable offline): crt.sh JSON -> (earliest not_before, number of distinct certificates, issuer names)."""
    try:
        rows = json.loads(text)
    except ValueError:
        return None, 0, ()
    if not isinstance(rows, list):
        return None, 0, ()
    dates, serials, issuers = [], set(), set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        d = _dt(r.get("not_before", ""))
        if d and d.year >= 1995:
            dates.append(d)
        serials.add(r.get("serial_number") or r.get("id") or len(serials))
        m = re.search(r"\bO=([^,]+)", r.get("issuer_name", "") or "")
        if m:
            issuers.add(m.group(1).strip().strip('"'))
    return (min(dates) if dates else None), len(serials), tuple(sorted(issuers))[:6]


def org_from_cert(cert: dict | None) -> str | None:
    """Pure function: ssl.getpeercert() dict -> organisation name in the subject, or None (DV certificates have none)."""
    for rdn in (cert or {}).get("subject", ()):
        for key, val in rdn:
            if key == "organizationName" and val.strip():
                return val.strip()
    return None


def _crt(domain: str, timeout: float):
    try:
        r = requests.get(CRT_URL, params={"q": domain, "output": "json"}, timeout=timeout)
        return parse_crt(r.text) if r.status_code == 200 else None
    except requests.RequestException:
        return None


def _tls_org(host: str, timeout: float) -> str | None:
    for h in (host, "www." + host):
        try:
            with socket.create_connection((h, 443), timeout=timeout) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=h) as s:
                    return org_from_cert(s.getpeercert())
        except (OSError, ssl.SSLError):
            continue
    return None


_cache: dict[str, tuple[float, CertInfo]] = {}


def lookup(domain: str, timeout: float = 6.0) -> CertInfo:
    now = time.time()
    hit = _cache.get(domain)
    if hit and hit[0] > now:
        return hit[1]
    with ThreadPoolExecutor(max_workers=2) as ex:
        fc, fo = ex.submit(_crt, domain, timeout), ex.submit(_tls_org, domain, min(timeout, 4.0))
        crt, org = fc.result(), fo.result()
    if crt is None and org is None:
        info = CertInfo(False, error="crt.sh did not answer and the site's certificate could not be read")
    else:
        first, n, issuers = crt if crt else (None, 0, ())
        info = CertInfo(True, first, n, issuers, org)
    _cache[domain] = (now + (86400 if info.succeeded else 300), info)
    return info
