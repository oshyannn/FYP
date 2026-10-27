"""
Explain a verdict: show what EVERY source says about a URL, and why the final result is what it is.

    python -m aidev.evaluation.check_sources https://example.com/page https://other.site/

Use it when a result looks wrong (e.g. a shady site shown as Safe): it says whether the URL was
trusted because of the manual whitelist, a Tranco rank, or a trusted path, and what PhishTank,
Google Safe Browsing and the model each returned.
"""
from __future__ import annotations

import os
import sys

from aidev.detection import detector
from aidev.detection import phishtank
from aidev.detection import safebrowsing
from aidev.core.common import DATA, LISTS, is_shared, lines
from aidev.core.features import get_host, normalize, registered_domain
from aidev.detection.predict import predict


def _rank(reg: str) -> int | None:
    for i, d in enumerate(lines(DATA / "tranco_top.txt"), 1):
        if d == reg:
            return i
    return None


def show(raw: str) -> None:
    url = normalize(raw)
    host, reg = get_host(url), registered_domain(url)
    print("=" * 78)
    print(f"URL     : {raw}\nhost    : {host}    registered domain: {reg}")

    manual_wl = {d.lower() for d in lines(LISTS / "whitelist.txt")}
    rank = _rank(reg)
    print("-- local lists")
    print(f"  manual blacklist     : {reg in detector.BLACKLIST_DOMAINS or host in detector.BLACKLIST_DOMAINS}")
    print(f"  in OpenPhish/URLhaus : {detector._key(url) in detector.FEED_URLS}")
    print(f"  manual whitelist     : {reg in manual_wl}")
    print(f"  Tranco rank          : {rank}  (whitelisted if rank <= {detector.WHITELIST_TOP_N}; "
          f"not_trusted: {reg in detector.NOT_TRUSTED})")
    print(f"  shared hosting       : {is_shared(host)}")
    print(f"  trusted prefix       : {detector._key(url).startswith(detector.TRUSTED_PREFIXES) if detector.TRUSTED_PREFIXES else False}")

    print("-- sources (queried directly, ignoring the whitelist shortcut)")
    pt = phishtank.check(url, os.getenv("PHISHTANK_API_KEY") or None)
    if not pt.succeeded:
        print(f"  PhishTank            : lookup failed ({pt.error})")
    else:
        print(f"  PhishTank            : found={pt.found} scope={pt.match_scope} verified={pt.verified} "
              f"valid={pt.valid} -> score {pt.risk_contribution}")
    sb = safebrowsing.check(url)
    if not sb.configured:
        print("  Google Safe Browsing : NOT CONFIGURED (GOOGLE_SAFE_BROWSING_API_KEY is not set in this terminal)")
    elif not sb.succeeded:
        print(f"  Google Safe Browsing : lookup failed ({sb.error})")
    else:
        print(f"  Google Safe Browsing : found={sb.found} type={sb.threat_type} -> score {sb.risk_contribution}")
    ml = predict(url)
    print("  ML model             : " + ("no opinion (model missing/unusable)" if ml is None
                                         else f"probability {ml['probability']:.1%}"))

    r = detector.analyze(raw)
    print("-- final verdict")
    print(f"  {r['status']}  score {r['risk_score']}  has_data={r['has_data']}  source={r['source']}")
    for reason in r["reasons"]:
        print(f"    - {reason}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for u in sys.argv[1:]:
        show(u)
