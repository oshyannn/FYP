"""Run the WHOLE detector (lists + APIs + models) on URLs:

    python -m aidev.tools.try_detector https://www.google.com https://xvideos.com

(`try_urls` only runs the URL model, so it cannot show whether the lists work.)
Prints: status, score, which source decided, and the first reasons. Unlisted URLs also call PhishTank / Safe Browsing / RDAP
and download the page, so they take a few seconds.
"""
import logging
import sys
import time

logging.basicConfig(level=logging.WARNING, format="  [%(levelname)s] %(message)s")
t0 = time.time()
from aidev.detection import detector  # noqa: E402  (importing it loads every list: that is the slow part)

print(f"detector ready in {time.time() - t0:.1f}s  | whitelist {len(detector.WHITELIST)}  adult {len(detector.ADULT)}  "
      f"feeds {len(detector.FEED_URLS)}  blacklist {len(detector.BLACKLIST_DOMAINS)}  top_n {detector.WHITELIST_TOP_N}\n")

urls = sys.argv[1:] or ["https://www.google.com", "https://www.tarc.edu.my", "https://xvideos.com", "https://test-blocked-example.com"]
for u in urls:
    t = time.time()
    r = detector.analyze(u)
    print(f"{u}\n   {r['status']}  score={r['risk_score']}  source={r['source']}  ({time.time() - t:.1f}s)")
    for why in r.get("reasons", [])[:3]:
        print("   -", why)
