import os

from phishtank import check

api_key = os.getenv("PHISHTANK_API_KEY", "")

test_url = "https://services-consignes-instructions.com/blog/blog.php"
verdict = check(test_url, api_key=api_key)

print("succeeded     :", verdict.succeeded)
print("found         :", verdict.found)
print("match_scope   :", verdict.match_scope)
print("matched_url   :", verdict.matched_url)
print("verified/valid:", verdict.verified, verdict.valid)
print("risk_score    :", verdict.risk_contribution)