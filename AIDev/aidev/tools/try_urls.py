"""Score URLs with the model only:   python -m aidev.tools.try_urls https://example.com https://other.site/login"""
import sys

from aidev.detection.predict import predict

for u in sys.argv[1:] or ["https://drive.google.com/drive/u/0/_/reauth", "https://www.phishtank.net/phish_archive.php",
                          "https://p581488.pro/index.php/suivi", "https://chartersbank.com/"]:
    r = predict(u)
    print(f"{u}\n   -> {'no opinion' if r is None else str(r['risk_score']) + '  (' + str(r['model_version']) + ')'}")
