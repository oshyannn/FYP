"""
Domain age that does not depend on one registry.

    from aidev.detection.domain_age import lookup
    a = lookup("sinchew.com.my")      # AgeInfo; a.days / a.kind / a.method / a.note

Why: RDAP (rdap.py) has no service for many country endings (.my, ...), so "no registration data" was common and the age
rule had nothing to say. This module tries, in order of trust:

  1. RDAP     registration date from the registry itself                          kind = "registered"
  2. WHOIS    port 43; the server is found from IANA ("refer:" line); creation date   kind = "registered"
  3. Archive  the Internet Archive's first capture of the domain (CDX API)           kind = "first_seen"
  4. CT logs  the first HTTPS certificate ever issued for the domain (cert_history.py)   kind = "first_seen"

The archive date is a LOWER BOUND: the site is at least that old, it may be older. It can show that a domain is NOT new,
but it can never show that a domain IS new (a brand-new domain simply has no capture yet), so detector.py only uses
"registered" dates to flag a new domain. WHOIS and the archive are asked in parallel, so the slowest one sets the delay
(timeout 4 s each). Everything is cached (24 h when found, 5 min when not). Failures are "no opinion", never evidence.
Privacy: only the domain name is sent, never the full URL.
"""
from __future__ import annotations

import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

from aidev.detection import cert_history, rdap

log = logging.getLogger(__name__)
WHOIS_PORT = 43
CDX_URL = "https://web.archive.org/cdx/search/cdx"
_CREATED = re.compile(
    r"^\s*(?:domain\s+)?(?:creat\w*(?:\s+(?:date|on|time))?|registered(?:\s+(?:on|date))?|registration\s+(?:date|time)|"
    r"record\s+created(?:\s+on)?|domain\s+registered|created\s+on)\s*[:.]+\s*(.+?)\s*$", re.I | re.M)
_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y.%m.%d",
            "%d-%b-%Y", "%d %b %Y", "%d %B %Y", "%d/%m/%Y", "%b %d %Y", "%B %d, %Y", "%Y/%m/%d", "%d-%m-%Y")


@dataclass(frozen=True)
class AgeInfo:
    succeeded: bool
    created: datetime | None = None
    kind: str | None = None            # "registered" (registry says so) | "first_seen" (first archived: a lower bound)
    method: str | None = None          # "rdap" | "whois" | "archive"
    note: str = ""                     # what was tried, in plain words (shown on the screens)

    @property
    def days(self) -> int | None:
        return None if self.created is None else max(0, (datetime.now(timezone.utc) - self.created).days)


def parse_date(text: str) -> datetime | None:
    """Pure function (testable offline): the date formats registries use -> aware datetime, else None."""
    t = (text or "").strip().split(" (")[0].strip().rstrip(".")
    t = re.sub(r"\s+(UTC|GMT)$", "", t, flags=re.I)
    t = re.sub(r"\s+\d{1,2}:\d{2}(:\d{2})?$", "", t) if re.match(r"^\d{1,2}[ /-]", t) else t
    t = t.replace("Z", "+00:00") if re.match(r"^\d{4}-\d\d-\d\dT", t) else t
    for fmt in _FORMATS:
        try:
            d = datetime.strptime(t, fmt)
        except ValueError:
            continue
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return None


def parse_whois(text: str) -> datetime | None:
    """Pure function: WHOIS text -> the EARLIEST creation date it states (a transfer or renewal line never wins)."""
    found = [d for d in (parse_date(m.group(1)) for m in _CREATED.finditer(text or "")) if d and d.year >= 1985]
    return min(found) if found else None


def parse_cdx(text: str) -> datetime | None:
    """Pure function: the first line of the CDX answer (output=json lists a header row, then [timestamp]) -> datetime."""
    m = re.search(r"\b(\d{14})\b", text or "")
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _whois_query(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode("ascii", "ignore"))
        chunks = []
        while len(chunks) < 64:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "ignore")


_servers: dict[str, str | None] = {}


def _whois_server(tld: str, timeout: float) -> str | None:
    if tld in _servers:
        return _servers[tld]
    server = None
    try:
        for line in _whois_query("whois.iana.org", tld, timeout).splitlines():
            if line.lower().startswith(("whois:", "refer:")):
                server = line.split(":", 1)[1].strip() or None
                break
    except OSError:
        return None                          # network trouble is not cached: try again next time
    _servers[tld] = server
    return server


def _by_whois(domain: str, timeout: float) -> datetime | None:
    server = _whois_server(domain.rsplit(".", 1)[-1], timeout)
    if not server:
        return None
    try:
        return parse_whois(_whois_query(server, domain, timeout))
    except OSError:
        return None


def _by_archive(domain: str, timeout: float) -> datetime | None:
    try:
        r = requests.get(CDX_URL, params={"url": domain, "limit": 1, "output": "json", "fl": "timestamp", "filter": "statuscode:200"},
                         timeout=timeout)
        return parse_cdx(r.text) if r.status_code == 200 else None
    except requests.RequestException:
        return None


_cache: dict[str, tuple[float, AgeInfo]] = {}


def lookup(registered_domain: str, timeout: float = 4.0) -> AgeInfo:
    now = time.time()
    hit = _cache.get(registered_domain)
    if hit and hit[0] > now:
        return hit[1]
    info = _lookup(registered_domain, timeout)
    _cache[registered_domain] = (now + (86400 if info.succeeded else 300), info)
    return info


def _lookup(domain: str, timeout: float) -> AgeInfo:
    tried = []
    r = rdap.lookup(domain, timeout=min(timeout, 3.0))
    if r.succeeded and r.created is not None:
        return AgeInfo(True, r.created, "registered", "rdap", "registration date from RDAP")
    tried.append("RDAP " + ("has no registration date" if r.succeeded else "has no service for this ending" if (r.error or "").startswith("no RDAP") else "did not answer"))
    with ThreadPoolExecutor(max_workers=3) as ex:                 # WHOIS, the archive and the CT logs in parallel
        fw, fa = ex.submit(_by_whois, domain, timeout), ex.submit(_by_archive, domain, timeout)
        fc = ex.submit(cert_history.lookup, domain)
        w, a, c = fw.result(), fa.result(), fc.result().first_seen
    if w is not None:
        return AgeInfo(True, w, "registered", "whois", "registration date from WHOIS (" + "; ".join(tried) + ")")
    tried.append("WHOIS gave no date")
    seen = [(d, m, t) for d, m, t in ((a, "archive", "first copy kept by the Internet Archive"),
                                      (c, "certs", "first HTTPS certificate in the public Certificate Transparency logs")) if d is not None]
    if seen:
        d, m, t = min(seen)
        return AgeInfo(True, d, "first_seen", m, f"{t}: the site is at least this old (" + "; ".join(tried) + ")")
    tried.append("no archived copy and no certificate history")
    return AgeInfo(False, None, None, None, "; ".join(tried))
