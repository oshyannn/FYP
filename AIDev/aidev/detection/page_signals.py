"""
More careful page signals, used ONLY for the explanation shown to the person (the per-kind percentages in page_threats.py).

    from aidev.detection.page_signals import extract
    s = extract(html, final_url)

Why this exists: content_features.py (what the trained content model reads) counts a few things very roughly, and the rough
counts make normal sites look dangerous when they are turned into percentages:
  * a hidden iframe: Google Tag Manager's standard <noscript><iframe height=0 width=0 style=display:none> is on a huge share of
    normal sites, and so are tracking pixels and ad frames;
  * "obfuscated" JavaScript: every \\uXXXX escape counted, so a Chinese / Malay / Tamil page whose JSON is written as
    \\u661f\\u6d32... scored as "heavily obfuscated";
  * "sensitive input": words like "social" or "pin" inside the name of an input (a share button, a pin-board widget).
These functions look at the same HTML more carefully. They do NOT change content_features.py, so the trained model, its
FEATURE_VERSION and the data stay valid: nothing here needs a retrain. Static text only; nothing is executed.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

# Hosts whose hidden frames / pixels are tracking or tag-manager plumbing on normal sites (suffix match on the host name).
TRACKER_HOSTS = (
    "googletagmanager.com", "google-analytics.com", "analytics.google.com", "doubleclick.net", "googlesyndication.com",
    "googleadservices.com", "google.com", "gstatic.com", "facebook.com", "facebook.net", "connect.facebook.net",
    "hotjar.com", "clarity.ms", "bing.com", "linkedin.com", "licdn.com", "twitter.com", "t.co", "tiktok.com", "yandex.ru",
    "yandex.com", "adsrvr.org", "criteo.com", "taboola.com", "outbrain.com", "scorecardresearch.com", "quantserve.com",
    "youtube.com", "youtube-nocookie.com",
)
# Only these <script type=...> hold code. JSON, JSON-LD, templates and importmaps are data, not JavaScript.
_JS_TYPES = ("", "text/javascript", "application/javascript", "application/x-javascript", "text/ecmascript", "module")

_OBF = re.compile(
    r"eval\s*\(|unescape\s*\(|atob\s*\(|fromCharCode|document\.write\s*\(|\\x[0-9a-fA-F]{2}"
    r"|\\u00[0-7][0-9a-fA-F]"            # \u00XX in the ASCII range: spelling plain letters as escapes IS an obfuscation trick
)                                         # (escapes for non-ASCII characters are ordinary text in JSON and are NOT counted)
_SENSITIVE = re.compile(
    r"card.?(?:number|no\b|num)|cc-?(?:num|number|csc|exp)|\bcvv\b|\bcvc\b|\bccv\b|expir|\botp\b|one.?time.?(?:pass|code)|"
    r"passcode|\biban\b|\bswift\b|routing.?number|\bssn\b|social.?security|passport|\bnric\b|mykad|ic.?number|mnemonic|"
    r"seed.?phrase|recovery.?phrase|private.?key|security.?code|\btac\b|account.?(?:number|no\b)|pin.?(?:code|number)", re.I)
_EXEC_LINK = re.compile(r"\.(exe|msi|apk|dmg|scr|bat|jar|pkg|crx|xpi|hta|lnk|ps1|vbs)(\?|#|$)", re.I)
_INPUT_SKIP = ("hidden", "submit", "button", "checkbox", "radio", "search", "image", "reset", "file")


def _host_matches(host: str, suffixes: tuple[str, ...]) -> bool:
    host = (host or "").lower()
    return any(host == s or host.endswith("." + s) for s in suffixes)


class _Scan(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.noscript = 0
        self.iframes: list[dict] = []
        self.inputs: list[dict] = []
        self.links: list[str] = []
        self._script_type: str | None = None
        self._script_buf: list[str] = []
        self.code_chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "noscript":
            self.noscript += 1
        elif tag == "script":
            self._script_type = (a.get("type") or "").strip().lower()
            self._script_buf = []
        elif tag == "iframe":
            style = a.get("style", "").replace(" ", "").lower()
            hidden = a.get("width") in ("0", "1") or a.get("height") in ("0", "1") or "display:none" in style or "visibility:hidden" in style
            self.iframes.append({"src": a.get("src", ""), "hidden": hidden, "in_noscript": self.noscript > 0})
        elif tag == "input":
            self.inputs.append({"type": (a.get("type") or "text").lower(),
                                "text": " ".join((a.get("name", ""), a.get("id", ""), a.get("placeholder", ""),
                                                  a.get("autocomplete", ""), a.get("aria-label", ""))).lower()})
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_endtag(self, tag):
        if tag == "noscript" and self.noscript:
            self.noscript -= 1
        elif tag == "script" and self._script_type is not None:
            if self._script_type in _JS_TYPES and not self._script_buf_is_empty():
                self.code_chunks.append("".join(self._script_buf))
            self._script_type, self._script_buf = None, []

    def _script_buf_is_empty(self) -> bool:
        return not "".join(self._script_buf).strip()

    def handle_data(self, data):
        if self._script_type is not None:
            self._script_buf.append(data)


def extract(html: str, final_url: str) -> dict:
    """Careful versions of the signals that page_threats.py turns into percentages."""
    html = (html or "")[:1_000_000]
    s = _Scan()
    try:
        s.feed(html)
        s.close()
    except Exception:
        pass                                                 # broken markup is normal; use what was parsed

    own = (urlsplit(final_url).hostname or "").lower()
    hidden_real, hidden_ignored = 0, 0
    for f in s.iframes:
        if not f["hidden"]:
            continue
        host = (urlsplit(urljoin(final_url, f["src"])).hostname or "").lower() if f["src"] else ""
        if f["in_noscript"] or _host_matches(host, TRACKER_HOSTS):
            hidden_ignored += 1                              # tag-manager / tracking plumbing, or only shown when JavaScript is off
        else:
            hidden_real += 1

    code = "\n".join(s.code_chunks)
    markers = len(_OBF.findall(code))
    density = markers / (len(code) / 1000 + 1)

    sensitive = [i for i in s.inputs if i["type"] not in _INPUT_SKIP and _SENSITIVE.search(i["text"])]
    exec_links = 0
    for h in s.links:
        try:
            if _EXEC_LINK.search(urlsplit(urljoin(final_url, h.strip())).path or ""):
                exec_links += 1
        except ValueError:
            continue
    return {
        "hidden_iframes": hidden_real,                       # hidden frames that are NOT tracker plumbing / noscript
        "hidden_iframes_ignored": hidden_ignored,
        "obfuscation_density": round(density, 2),            # same formula as content_features, but only real code and ASCII escapes
        "obfuscation_markers": markers,
        "sensitive_inputs": len(sensitive),
        "sensitive_input_names": [i["text"].split()[0] if i["text"].split() else "?" for i in sensitive][:5],
        "exec_links": exec_links,                            # links to program files (.exe .msi .apk ...), archives not counted
        "own_host": own,
    }
