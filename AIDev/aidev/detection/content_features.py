"""
Page-content features for the content model (what Google-style detectors look at), computed from static HTML.

    extract(html, final_url, redirects, tls_invalid) -> {feature: number}

No dependencies (stdlib HTML parser). Bump CONTENT_FEATURE_VERSION when the meaning of a feature changes; the model
file stores it and predict_content.py refuses a mismatched model. Training re-extracts from the saved HTML, so a
change here needs retraining but NOT a new crawl.

Deliberately excluded: the URL scheme and anything that differs systematically between how phishing and benign
pages are collected (see crawl_pages.py), so the model cannot learn the collection method instead of the phishing.
"""
from __future__ import annotations

import math
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from aidev.core.features import BRANDS, split_host

CONTENT_FEATURE_VERSION = 2

SENSITIVE_WORDS = ("password", "passcode", "verify", "account", "suspend", "confirm", "security", "bank", "credit card",
                   "card number", "cvv", "ssn", "social security", "otp", "wallet", "recovery", "unusual activity", "limited")
LOGIN_TITLE_WORDS = ("login", "log in", "sign in", "signin", "verify", "account", "secure", "update", "confirm", "webmail")
_OBF = re.compile(r"eval\s*\(|unescape\s*\(|atob\s*\(|fromCharCode|document\.write\s*\(|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
# Not every phishing page has a password box: bank pages ask for card/OTP/ID numbers, wallet scams ask for seed phrases,
# "plugin"/"app" pages push a download, and redirector pages only send you on to another site.
_SENSITIVE_INPUT = re.compile(r"card|cc-?num|cvv|cvc|ccv|expir|otp|pin\b|passcode|iban|swift|routing|ssn|social|passport|"
                              r"nric|mykad|seed|mnemonic|recovery|private.?key|secret|security.?code|tac\b|account.?n", re.I)
_JS_REDIRECT = re.compile(r"(window|document|top|self)\.location(\.href)?\s*=|location\.(replace|assign)\s*\(|location\.href\s*=", re.I)
_OAUTH_LINK = re.compile(r"oauth|authorize|consent|/o/oauth2|openid|login\.microsoftonline|accounts\.google", re.I)
_DOWNLOAD_EXT = re.compile(r"\.(exe|msi|apk|dmg|crx|xpi|scr|bat|jar|zip|rar|pkg)(\?|$)", re.I)
_INSTALL_WORDS = ("install extension", "add to chrome", "install plugin", "download plugin", "update required", "install the app",
                  "download the app", "update your browser", "install now", "plug-in")
_RIGHTCLICK = re.compile(r"contextmenu|event\.button\s*==\s*2|oncontextmenu\s*=\s*[\"']?\s*return\s+false", re.I)

FEATURE_NAMES = [
    "n_forms", "has_password_field", "n_password_fields", "n_inputs", "n_hidden_inputs", "hidden_input_ratio",
    "form_external_action", "form_null_action", "form_script_or_mail_action", "has_submit", "has_email_field",
    "n_links", "ext_link_ratio", "null_link_ratio", "n_images", "ext_image_ratio",
    "log_text_len", "n_words", "n_tags", "text_per_tag", "log_html_len",
    "title_len", "title_empty", "title_matches_domain", "title_login_word", "brand_in_title_not_domain",
    "brand_in_text_not_domain", "n_sensitive_words",
    "n_scripts", "log_inline_script_len", "ext_script_ratio", "obfuscation_density", "rightclick_blocked",
    "n_iframes", "hidden_iframe", "meta_refresh", "favicon_missing", "favicon_external", "ext_resource_ratio",
    "n_sensitive_inputs", "js_redirect", "n_download_links", "install_words", "oauth_links", "thin_page",
    "has_copyright", "n_redirects", "redirect_cross_domain", "tls_invalid", "has_lang_attr",
]


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self._skip = 0                                   # inside <script>/<style>
        self._in_script = False
        self.text: list[str] = []
        self.forms: list[dict] = []
        self.inputs: list[dict] = []
        self.links: list[str] = []
        self.images: list[str] = []
        self.scripts_src: list[str] = []
        self.inline_scripts: list[str] = []
        self.styles_src: list[str] = []
        self.iframes: list[dict] = []
        self.icons: list[str] = []
        self.meta_refresh = False
        self.has_lang = False
        self.n_tags = 0
        self.buttons = 0
        self._cur_script: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        self.n_tags += 1
        if tag == "html" and a.get("lang"):
            self.has_lang = True
        elif tag == "title":
            self._in_title = True
        elif tag in ("script", "style"):
            self._skip += 1
            self._in_script = tag == "script"
            if tag == "script" and a.get("src"):
                self.scripts_src.append(a["src"])
        elif tag == "form":
            self.forms.append({"action": a.get("action", ""), "method": a.get("method", "").lower()})
        elif tag == "input":
            self.inputs.append({"type": (a.get("type") or "text").lower(), "name": (a.get("name") or "").lower(),
                                "hint": " ".join((a.get("placeholder", ""), a.get("autocomplete", ""), a.get("id", ""),
                                                  a.get("aria-label", ""))).lower()})
        elif tag == "button":
            self.buttons += 1
        elif tag == "a" and "href" in a:
            self.links.append(a["href"])
        elif tag == "img" and a.get("src"):
            self.images.append(a["src"])
        elif tag == "iframe":
            style = (a.get("style") or "").replace(" ", "").lower()
            hidden = a.get("width") in ("0", "1") or a.get("height") in ("0", "1") or "display:none" in style or "visibility:hidden" in style
            self.iframes.append({"src": a.get("src", ""), "hidden": hidden})
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            if "icon" in rel and a.get("href"):
                self.icons.append(a["href"])
            elif "stylesheet" in rel and a.get("href"):
                self.styles_src.append(a["href"])
        elif tag == "meta" and (a.get("http-equiv") or "").lower() == "refresh":
            self.meta_refresh = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style") and self._skip:
            self._skip -= 1
            if tag == "script":
                if self._cur_script:
                    self.inline_scripts.append("".join(self._cur_script))
                self._cur_script = []
                self._in_script = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._skip:
            if self._in_script:
                self._cur_script.append(data)
        else:
            self.text.append(data)


def _reg(host: str | None) -> str:
    host = (host or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return split_host(host)[1] or host if host else ""


def _alnum(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def extract(html: str, final_url: str, redirects: list[str] | None = None, tls_invalid: bool = False) -> dict[str, float]:
    html = (html or "")[:1_000_000]
    c = _Collector()
    try:
        c.feed(html)
        c.close()
    except Exception:
        pass                                              # broken markup is normal; use what was parsed

    base_host = urlsplit(final_url).hostname or ""
    my_reg = _reg(base_host)
    my_label = my_reg.split(".")[0] if my_reg else ""

    def foreign(u: str) -> bool | None:
        """True/False if u points to another/the same registered domain; None if relative/no host."""
        u = (u or "").strip()
        if not u or u.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        host = urlsplit(urljoin(final_url, u)).hostname
        return None if not host else _reg(host) != my_reg

    text = " ".join(" ".join(c.text).split())
    low_text = text.lower()
    title = " ".join(c.title.split())
    low_title = title.lower()
    n_inputs = len(c.inputs)
    hidden = sum(i["type"] == "hidden" for i in c.inputs)
    pw = sum(i["type"] == "password" for i in c.inputs)

    actions = [f["action"].strip() for f in c.forms]
    ext_action = any(foreign(a) is True for a in actions)
    null_action = any((a == "" or a.startswith(("#", "javascript:"))) for a in actions)
    script_or_mail = any(a.lower().startswith("mailto:") or re.search(r"\.(php|asp|aspx|cgi)(\?|$)", a.lower()) for a in actions)

    link_flags = [foreign(h) for h in c.links]
    http_links = [f for f in link_flags if f is not None]
    null_links = sum(1 for h in c.links if (h or "").strip() in ("", "#") or (h or "").strip().lower().startswith("javascript:"))
    img_flags = [f for f in (foreign(u) for u in c.images) if f is not None]
    script_flags = [f for f in (foreign(u) for u in c.scripts_src) if f is not None]
    css_flags = [f for f in (foreign(u) for u in c.styles_src) if f is not None]
    res_flags = img_flags + script_flags + css_flags

    inline = "\n".join(c.inline_scripts)
    obf = len(_OBF.findall(inline))
    brand_title = any(b in _alnum(title) and b != my_label and b not in my_reg for b in BRANDS)
    head_text = low_text[:3000]
    brand_text = any(b in _alnum(head_text) and b != my_label and b not in my_reg for b in BRANDS)

    icon_f = [foreign(u) for u in c.icons]
    redirects = redirects or []
    redir_cross = any(_reg(urlsplit(u).hostname) != my_reg for u in redirects)

    def ratio(flags: list[bool]) -> float:
        return sum(flags) / len(flags) if flags else 0.0

    n_sens_inputs = sum(bool(_SENSITIVE_INPUT.search(i["name"] + " " + i["hint"])) for i in c.inputs if i["type"] not in ("hidden", "submit", "button"))
    n_words = len(text.split())

    return {
        "n_sensitive_inputs": n_sens_inputs,
        "js_redirect": int(bool(_JS_REDIRECT.search(inline))),
        "n_download_links": sum(bool(_DOWNLOAD_EXT.search(h or "")) for h in c.links),
        "install_words": int(any(w in low_text for w in _INSTALL_WORDS)),
        "oauth_links": sum(bool(_OAUTH_LINK.search(h or "")) for h in c.links),
        "thin_page": int(n_words < 60 and len(c.links) < 6),
        "n_forms": len(c.forms),
        "has_password_field": int(pw > 0),
        "n_password_fields": pw,
        "n_inputs": n_inputs,
        "n_hidden_inputs": hidden,
        "hidden_input_ratio": hidden / n_inputs if n_inputs else 0.0,
        "form_external_action": int(ext_action),
        "form_null_action": int(null_action),
        "form_script_or_mail_action": int(script_or_mail),
        "has_submit": int(c.buttons > 0 or any(i["type"] in ("submit", "image") for i in c.inputs)),
        "has_email_field": int(any(i["type"] == "email" or "email" in i["name"] or "user" in i["name"] for i in c.inputs)),
        "n_links": len(c.links),
        "ext_link_ratio": ratio(http_links),
        "null_link_ratio": null_links / len(c.links) if c.links else 0.0,
        "n_images": len(c.images),
        "ext_image_ratio": ratio(img_flags),
        "log_text_len": math.log1p(len(text)),
        "n_words": len(text.split()),
        "n_tags": c.n_tags,
        "text_per_tag": len(text) / c.n_tags if c.n_tags else 0.0,
        "log_html_len": math.log1p(len(html)),
        "title_len": len(title),
        "title_empty": int(not title),
        "title_matches_domain": int(bool(my_label) and my_label in _alnum(title)),
        "title_login_word": int(any(w in low_title for w in LOGIN_TITLE_WORDS)),
        "brand_in_title_not_domain": int(brand_title),
        "brand_in_text_not_domain": int(brand_text),
        "n_sensitive_words": sum(low_text.count(w) for w in SENSITIVE_WORDS),
        "n_scripts": len(c.scripts_src) + len(c.inline_scripts),
        "log_inline_script_len": math.log1p(len(inline)),
        "ext_script_ratio": ratio(script_flags),
        "obfuscation_density": obf / (len(inline) / 1000 + 1),
        "rightclick_blocked": int(bool(_RIGHTCLICK.search(html))),
        "n_iframes": len(c.iframes),
        "hidden_iframe": int(any(i["hidden"] for i in c.iframes)),
        "meta_refresh": int(c.meta_refresh),
        "favicon_missing": int(not c.icons),
        "favicon_external": int(any(f is True for f in icon_f)),
        "ext_resource_ratio": ratio(res_flags),
        "has_copyright": int("©" in text or "copyright" in low_text or "&copy" in html.lower()),
        "n_redirects": len(redirects),
        "redirect_cross_domain": int(redir_cross),
        "tls_invalid": int(tls_invalid),
        "has_lang_attr": int(c.has_lang),
    }


def vector(html: str, final_url: str, redirects: list[str] | None = None, tls_invalid: bool = False) -> list[float]:
    f = extract(html, final_url, redirects, tls_invalid)
    return [f[n] for n in FEATURE_NAMES]
