"""
Lexical URL features, shared by train.py and predict.py (never duplicate this logic).

Rules:
  * Computed from the URL string alone: no network, no WHOIS, no page content.
  * Scheme (http/https) and the query string are deliberately EXCLUDED. Benign
    training URLs are synthetic, so anything that differs systematically between
    how positives and negatives were built would let the model cheat.
  * Changing the feature list or order requires retraining; FEATURE_NAMES is
    stored inside model.joblib and checked at load time.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlsplit

try:  # optional; falls back to a naive split
    import tldextract

    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)  # offline, bundled snapshot
except Exception:  # pragma: no cover
    _EXTRACT = None

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "wallet", "suspend", "invoice", "billing", "support",
)
RISKY_TLDS = {
    "zip", "mov", "top", "xyz", "icu", "click", "gq", "tk", "ml", "cf", "ga",
    "work", "rest", "cyou", "buzz", "monster", "sbs", "info",
}
# Well-known brands phishers imitate. A brand name inside a host whose registered domain is NOT that
# brand ("paypal-secure-login.xyz", "apple.id-check.top") is a classic phishing pattern.
BRANDS = (
    "paypal", "google", "apple", "microsoft", "amazon", "facebook", "instagram", "netflix", "whatsapp",
    "linkedin", "dropbox", "adobe", "docusign", "dhl", "fedex", "usps", "maybank", "cimb", "hsbc",
    "chase", "wellsfargo", "citibank", "bankofamerica", "steam", "binance", "coinbase", "metamask",
    "outlook", "office365", "icloud", "yahoo", "ebay", "alibaba", "lazada", "shopee", "touchngo",
    "tiktok", "telegram", "spotify", "airbnb", "booking", "rakuten", "lloyds", "barclays", "santander",
)
RISKY_EXTENSIONS = (".php", ".exe", ".zip", ".apk", ".scr", ".js", ".html", ".htm", ".asp", ".aspx", ".jsp")
_VOWELS = set("aeiou")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# Bump whenever extract() changes meaning, so an old model.joblib is refused instead of silently misused.
FEATURE_VERSION = 3

FEATURE_NAMES = [
    "host_length",
    "path_length",
    "num_dots_host",
    "num_hyphens_host",
    "num_digits_host",
    "digit_ratio_host",
    "num_subdomains",
    "host_is_ip",
    "has_at_symbol",
    "num_path_segments",
    "num_suspicious_words",
    "risky_tld",
    "host_entropy",
    "has_punycode",
    "longest_host_label",
    "path_special_chars",
    # --- added in feature version 3
    "reg_label_length",
    "tld_length",
    "num_host_tokens",
    "avg_token_length",
    "max_consonant_run",
    "vowel_ratio_host",
    "digit_letter_switches",
    "brand_mismatch",
    "path_has_risky_ext",
    "path_pct_encoded",
    "path_digit_ratio",
    "longest_path_token",
    "path_double_slash",
]


def normalise(url: str) -> str:
    """Add a scheme if missing so urlsplit finds the host."""
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def split_host(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registered_domain, suffix)."""
    host = host.lower().strip(".")
    if _EXTRACT is not None:
        e = _EXTRACT(host)
        reg = f"{e.domain}.{e.suffix}" if e.suffix else e.domain
        return e.subdomain, reg, e.suffix
    parts = host.split(".")
    if len(parts) <= 2:
        return "", host, parts[-1] if len(parts) > 1 else ""
    return ".".join(parts[:-2]), ".".join(parts[-2:]), parts[-1]


def registered_domain(url: str) -> str:
    """Used as the group key when splitting train/test by domain."""
    host = (urlsplit(normalise(url)).hostname or "").lower()
    return split_host(host)[1] or host


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def extract(url: str) -> dict[str, float]:
    """Return {feature_name: value}. Raises ValueError if no host can be found."""
    parts = urlsplit(normalise(url))
    host = (parts.hostname or "").lower()
    if not host or not re.fullmatch(r"[a-z0-9._-]+|[0-9a-f:]+", host) or "." not in host:
        raise ValueError(f"no valid host in url: {url!r}")
    # Formatting differences between data sources must not become signals:
    # "https://x.com", "https://x.com/" and "https://www.x.com/" are the same page.
    path = (parts.path or "").lower().rstrip("/")
    if host.startswith("www."):
        host = host[4:]

    sub, reg, suffix = split_host(host)
    is_ip = bool(_IP_RE.match(host))
    digits = sum(ch.isdigit() for ch in host)
    labels = host.split(".")
    segments = [s for s in path.split("/") if s]
    text = host + path

    # ---- version-3 helpers (host letters only, so digits/dots do not distort vowel statistics)
    reg_label = reg[: -(len(suffix) + 1)] if suffix and reg.endswith("." + suffix) else reg
    host_tokens = [t for t in re.split(r"[.\-]", host) if t]
    letters = [c for c in host if c.isalpha()]
    run = best = 0
    for c in letters:
        run = run + 1 if c not in _VOWELS else 0
        best = max(best, run)
    switches = sum(a.isdigit() != b.isdigit() for a, b in zip(host, host[1:]) if a.isalnum() and b.isalnum())
    brand_hit = any(b in host and reg_label != b for b in BRANDS)
    path_tokens = [t for t in re.split(r"[/._\-]", path) if t]

    return {
        "host_length": len(host),
        "path_length": len(path),
        "num_dots_host": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_digits_host": digits,
        "digit_ratio_host": digits / len(host),
        "num_subdomains": 0 if is_ip else len([x for x in sub.split(".") if x]),
        "host_is_ip": int(is_ip),
        "has_at_symbol": int("@" in (parts.netloc or "")),
        "num_path_segments": len(segments),
        "num_suspicious_words": sum(w in text for w in SUSPICIOUS_WORDS),
        "risky_tld": int(suffix.split(".")[-1] in RISKY_TLDS),
        "host_entropy": _entropy(host),
        "has_punycode": int("xn--" in host),
        "longest_host_label": max(len(x) for x in labels),
        "path_special_chars": sum(not (c.isalnum() or c in "/.-_") for c in path),
        "reg_label_length": len(reg_label),
        "tld_length": len(suffix),
        "num_host_tokens": len(host_tokens),
        "avg_token_length": sum(map(len, host_tokens)) / max(len(host_tokens), 1),
        "max_consonant_run": best,
        "vowel_ratio_host": (sum(c in _VOWELS for c in letters) / len(letters)) if letters else 0.0,
        "digit_letter_switches": switches,
        "brand_mismatch": int(brand_hit),
        "path_has_risky_ext": int(path.endswith(RISKY_EXTENSIONS)),
        "path_pct_encoded": path.count("%"),
        "path_digit_ratio": (sum(c.isdigit() for c in path) / len(path)) if path else 0.0,
        "longest_path_token": max((len(t) for t in path_tokens), default=0),
        "path_double_slash": int("//" in path),
    }


def vector(url: str) -> list[float]:
    f = extract(url)
    return [f[name] for name in FEATURE_NAMES]


# --- names used by detector.py -------------------------------------------------
normalize = normalise


def get_host(url: str) -> str:
    return (urlsplit(normalise(url)).hostname or "").lower()


def extract_features(url: str) -> list[float]:
    """Feature vector in FEATURE_NAMES order (same as vector())."""
    return vector(url)
