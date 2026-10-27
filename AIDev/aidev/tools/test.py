"""
Quick standalone test — confirms whether your PHISHTANK_API_KEY is being read,
and whether this specific URL matches PhishTank's exact-URL database.

HOW TO USE
1. Change YOUR_EMAIL below to your own email (any Gmail works).
2. Save this file, e.g. as test_phishtank.py
3. In a NEW terminal window (must be opened after setx + full VS Code restart):
       python test_phishtank.py
"""

import base64
import os

import requests

# --- CHANGE THIS ONE LINE -----------------------------------------------
YOUR_EMAIL = "ongsy-wm23@student.tarc.edu.my"
# --------------------------------------------------------------------------

USER_AGENT = f"phishtank/urldetect-fyp (+{YOUR_EMAIL})"

api_key = os.getenv("PHISHTANK_API_KEY", "")
print("API key loaded:", bool(api_key), "| length:", len(api_key))

# Try a few likely variants of the same URL — PhishTank matches full strings,
# not domains, so scheme / trailing slash / query string differences all miss.
urls_to_try = [
    "https://services-consignes-instructions.com/blog/blog.php",
    "http://services-consignes-instructions.com/blog/blog.php",
    "https://services-consignes-instructions.com/",
    "http://services-consignes-instructions.com/",
]

for url in urls_to_try:
    encoded = base64.b64encode(url.encode()).decode()
    response = requests.post(
        "https://checkurl.phishtank.com/checkurl/",
        data={"url": encoded, "format": "json", "app_key": api_key},
        headers={"User-Agent": USER_AGENT},
        timeout=10,
    )
    print("\n---", url)
    print("status:", response.status_code)
    print("content-type:", response.headers.get("Content-Type"))
    print(response.text[:400])