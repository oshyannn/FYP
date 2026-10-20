"""
Fetch a page's HTML for analysis. Nothing is executed: no JavaScript, no cookies, no downloads.

Safety rules (this runs on YOUR machine against addresses chosen by strangers):
  * only http/https, and only to PUBLIC addresses: every hop of every redirect is resolved and refused if it
    points to localhost / private network / link-local (otherwise a page could make your backend probe your LAN)
  * at most MAX_REDIRECTS redirects, MAX_BYTES of body, short timeouts, HTML/text content types only
  * a bad TLS certificate does not stop the fetch (phishing sites often have one); it is reported as tls_invalid
  * if the address answers with a program file (exe/msi/apk...), the body is NOT read: only the headers are
    looked at and the file name is reported in Page.download

Limits: server-rendered HTML only. Pages built by JavaScript look empty here. The fetch reveals your IP address
to the site being checked. DNS can change between the check and the request (rebinding); not defended here.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import unquote, urljoin, urlsplit

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_BYTES = 1_000_000
MAX_REDIRECTS = 5
TIMEOUT = (3.0, 4.0)                      # connect, read
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; UrlDetectFYP/1.0)", "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"}
_HTML_TYPES = ("text/html", "application/xhtml", "text/plain", "application/xml", "text/xml")

# Same list as RISKY_NAME / RISKY_MIME in extension/background.js (keep them in step).
RISKY_FILE = re.compile(r"\.(exe|msi|scr|bat|cmd|pif|apk|jar|js|jse|vbs|vbe|ps1|hta|lnk|reg|dll|sh|dmg|pkg|iso|img|docm|xlsm|pptm)$", re.I)
_BINARY_FILE = re.compile(r"\.(exe|msi|scr|apk|dmg|pkg|iso|img|dll|jar|lnk|hta|pif)$", re.I)   # clearly not a web page
_RISKY_MIME = re.compile(r"x-msdownload|x-msdos-program|x-dosexec|vnd\.android\.package-archive|x-sh\b|x-bat|java-archive|"
                         r"x-apple-diskimage|x-msi\b", re.I)
_FILENAME = re.compile(r"""filename\*?\s*=\s*(?:UTF-8'')?"?([^";]+)"?""", re.I)


@dataclass
class Page:
    ok: bool
    url: str                                  # final URL after redirects
    status: int = 0
    html: str = ""
    redirects: list[str] = field(default_factory=list)   # every URL visited before the final one
    tls_invalid: bool = False
    error: str | None = None
    download: str | None = None               # file name when the address itself is a program-file download


def risky_download(url: str, headers) -> str | None:
    """File name if this response is a program/script file download (headers only), else None."""
    disp = headers.get("Content-Disposition") or ""
    ctype = (headers.get("Content-Type") or "").lower()
    m = _FILENAME.search(disp)
    name = unquote(m.group(1)).strip() if m else ""
    if not name:
        name = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    attachment = "attachment" in disp.lower()
    is_html = any(t in ctype for t in _HTML_TYPES)
    if RISKY_FILE.search(name) and (attachment or (_BINARY_FILE.search(name) and not is_html)):
        return name
    if _RISKY_MIME.search(ctype):
        return name or ctype
    return None


def is_public_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    addrs = {i[4][0].split("%")[0] for i in infos}
    return bool(addrs) and all(ipaddress.ip_address(a).is_global for a in addrs)


def _ok_url(url: str, allow_private: bool) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "unsupported URL"
    if not allow_private and not is_public_host(parts.hostname):
        try:
            socket.getaddrinfo(parts.hostname, None)
        except OSError:
            return "address does not resolve (site gone or DNS blocked)"
        return "address is not public"
    return None


def fetch(url: str, allow_private: bool = False, deadline: float = 7.0) -> Page:
    """Never raises. `deadline` = seconds for the whole fetch incl. redirects. allow_private is for tests only."""
    t_end = time.monotonic() + deadline
    visited: list[str] = []
    tls_invalid = False
    cur = url
    for _ in range(MAX_REDIRECTS + 1):
        left = t_end - time.monotonic()
        if left <= 0.3:
            return Page(False, cur, redirects=visited, tls_invalid=tls_invalid, error="timed out")
        timeout = (min(TIMEOUT[0], left), min(TIMEOUT[1], left))
        bad = _ok_url(cur, allow_private)
        if bad:
            return Page(False, cur, redirects=visited, tls_invalid=tls_invalid, error=bad)
        try:
            try:
                r = requests.get(cur, headers=HEADERS, timeout=timeout, allow_redirects=False, stream=True, verify=True)
            except requests.exceptions.SSLError:
                tls_invalid = True
                r = requests.get(cur, headers=HEADERS, timeout=timeout, allow_redirects=False, stream=True, verify=False)
        except requests.RequestException as exc:
            return Page(False, cur, redirects=visited, tls_invalid=tls_invalid, error=f"request failed ({type(exc).__name__})")

        try:
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                visited.append(cur)
                cur = urljoin(cur, r.headers["Location"])
                continue
            if r.status_code < 400:
                dl = risky_download(cur, r.headers)
                if dl:                                   # headers only: the file body is never read
                    return Page(False, cur, r.status_code, redirects=visited, tls_invalid=tls_invalid,
                                error="file download", download=dl)
            ctype = (r.headers.get("Content-Type") or "").lower()
            chunks, size = [], 0
            for chunk in r.iter_content(chunk_size=16384):
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BYTES:
                    break
            raw = b"".join(chunks)[:MAX_BYTES]
            looks_html = any(t in ctype for t in _HTML_TYPES) or (not ctype and raw.lstrip()[:1] == b"<")
            if not looks_html:
                return Page(False, cur, r.status_code, redirects=visited, tls_invalid=tls_invalid, error="not an HTML page")
            html = raw.decode(r.encoding or "utf-8", errors="replace")
            return Page(r.status_code == 200, cur, r.status_code, html, visited, tls_invalid,
                        None if r.status_code == 200 else f"HTTP {r.status_code}")
        except requests.RequestException as exc:
            return Page(False, cur, redirects=visited, tls_invalid=tls_invalid, error=f"read failed ({type(exc).__name__})")
        finally:
            r.close()
    return Page(False, cur, redirects=visited, tls_invalid=tls_invalid, error="too many redirects")
