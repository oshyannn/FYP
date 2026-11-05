# Age-rule fix for detector.py — install

Extract this zip INTO your FYP folder (merge folders). Delete this file afterwards.
Tell your ML collaborator first: this changes detection results (see below).

## New file (nothing is overwritten)
AIDev/aidev/tools/apply_age_rule_patch.py

## Steps
1. cd AIDev ; python -m aidev.tools.apply_age_rule_patch
   - makes aidev/detection/detector.py.bak (a backup), then 6 small edits inside detector.py
   - if you already ran the FIRST version of this fix, it restores the original from the backup and applies this one
   - if detector.py was edited in one of those spots it changes NOTHING and tells you which edit did not match
   - safe to run twice
2. Restart the backend: python app.py   (results are cached for up to an hour; rescan after restarting)

## What changes
Before: a domain older than 2 years always pushed a suspicious URL-model score down to 29, so a site the model rated 85%
ended up "Unknown" while the screen also said "no strong phishing signal".
After:  age outweighs the model only when something else vouches for the site:
        - it is in the Tranco top 300,000, OR
        - Wikidata lists it as an official website, OR
        - its certificate names an organisation.
        Otherwise the model's suspicion stays and the site is Suspicious, with the reason
        "age alone does not outweigh the model's suspicion because nothing else vouches for the site".
        When age DOES outweigh the model, the text now says so (and the summary says "Not confirmed safe")
        instead of "no strong phishing signal".
Wording: when the ONLY warning is the URL model, and the page was read and the page checks found nothing bad, the summary says:
        "Not a recognised site, no clear malicious behaviour" - nothing confirms it is an established or official website, but
        no automatic download, no hidden or obfuscated script and no fake login / payment form was found; still be careful with
        ads, pop-ups and redirects. If the page could not be read, or any other check also warns, it stays "Suspicious: be careful".
        When age outweighed the model: "No clear malicious behaviour found" (not confirmed safe).
Not changed: lists, PhishTank, Safe Browsing, the page model, thresholds, the established-site rule.

## Undo
Copy aidev/detection/detector.py.bak back over detector.py.
