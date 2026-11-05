"""Fixes how an old domain may outweigh the URL model in aidev/detection/detector.py, and words the result plainly.

Run from the AIDev folder:   python -m aidev.tools.apply_age_rule_patch   (safe to run twice)

Before:  a domain older than 2 years (3 for "first seen") always pushed a suspicious URL-model score down to 29, so a
         site the model rated 85% ended up "Unknown", and the screen said both "85%" and "no strong phishing signal".
After:   age only outweighs the model when something else vouches for the site: it is among the 300,000 most visited
         sites, OR Wikidata lists it as an official website, OR its certificate names an organisation.
         Otherwise the model's suspicion stays (Suspicious) and the reason says why age alone was not enough.
Wording: when the ONLY warning is the URL model and the page was read and showed nothing bad, the summary says so:
         "Not a recognised site, no clear malicious behaviour" (no automatic download, no hidden or obfuscated script,
         no fake login or payment form) instead of a bare "Suspicious".

It makes a backup (detector.py.bak), checks that every piece of text it replaces exists exactly once, and writes
nothing at all if any piece is missing (for example because detector.py was edited in that spot).
If the first version of this fix was already applied, it restores the original from the backup and applies this one.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

TARGET = Path(__file__).resolve().parents[1] / "detection" / "detector.py"
MARK = "only_model = not any("            # present once this version is applied
OLD_MARK = "outweighed = False"             # present after the first version of this fix

EDITS = [
    # 1. a flag that remembers "the model was suspicious but age + other evidence outweighed it"
    ('''    age_new = False
    age_days = None
    age_kind = None
    rank_ = None
    wd_ = cert_ = None
''', '''    age_new = False
    age_days = None
    age_kind = None
    rank_ = None
    wd_ = cert_ = None
    outweighed = False      # the URL model was suspicious, but age plus other evidence outweighed it
'''),
    # 2. age only outweighs the model when something else vouches for the site
    ('''        elif old_enough and not non_ml and score is not None and score >= THRESHOLD_SUSPICIOUS:
            score = THRESHOLD_SUSPICIOUS - 1
            reasons.append(f"Domain is at least {age_days // 365} years old, which outweighs the model's weak suspicion")
            ck.add("domain_age", "info", f"At least {age_days // 365} years old ({via}), which outweighs the model's weak suspicion")
''', '''        elif old_enough and not non_ml and score is not None and score >= THRESHOLD_SUSPICIOUS and (
                popularity.rank(reg) is not None or (wd_.succeeded and wd_.found) or (cert_.succeeded and cert_.org)):
            score = THRESHOLD_SUSPICIOUS - 1
            outweighed = True
            reasons.append(f"Domain is at least {age_days // 365} years old and something else vouches for it (popularity rank, official-website record or certificate owner), which outweighs the model's suspicion")
            ck.add("domain_age", "info", f"At least {age_days // 365} years old ({via}), and something else vouches for the site, which outweighs the model's suspicion")
        elif old_enough and not non_ml and score is not None and score >= THRESHOLD_SUSPICIOUS:
            reasons.append(f"Domain is at least {age_days // 365} years old, but nothing else vouches for it (not among the most visited sites, no official-website record, no certificate owner), so age alone does not outweigh the model's suspicion")
            ck.add("domain_age", "info", f"At least {age_days // 365} years old ({via}), but age alone does not outweigh the model's suspicion because nothing else vouches for the site")
'''),
    # 3. no more "no strong phishing signal" next to an 85% model score
    ('''    if _status(score) == "Safe" and not non_ml:
        reasons.append("No strong phishing signal from the model. This is not a guarantee that the site is safe.")
        return finish("Unknown", None, "model")
''', '''    if _status(score) == "Safe" and not non_ml:
        reasons.append(("The URL model was suspicious, but the site's age and other evidence outweigh it. " if outweighed
                        else "No strong phishing signal from the model. ") + "This is not a guarantee that the site is safe.")
        return finish("Unknown", None, "model")
'''),
    # 4. pass the flag to the summary
    ('''{"established": established, "checked": score is not None}''',
     '''{"established": established, "checked": score is not None, "outweighed": outweighed}'''),
    # 5. summary text when age outweighed the model but nothing confirms the site
    ('''    else:
        label, conf = "No warning signs found", "low" if len(missing) >= 3 else "medium"
''', '''    elif ctx.get("outweighed"):
        label, conf = "No clear malicious behaviour found", "low"
        text = ("The web address looked suspicious to the URL model, but the site is old and something else vouches for it, so it was not "
                "marked as a threat. It is not confirmed safe, so be careful with ads, pop-ups, passwords and payments.")
    else:
        label, conf = "No warning signs found", "low" if len(missing) >= 3 else "medium"
'''),
    # 6. Suspicious because of the URL model alone, and the page showed nothing bad: say exactly that
    ('''    elif status == "Suspicious":
        label, conf = "Suspicious: be careful", "medium"
        text = "Some warning signs were found but not enough to call the site malicious. Do not enter passwords or payment details unless you are sure it is the real site."
''', '''    elif status == "Suspicious":
        only_model = not any(c["state"] == "match" and c["effect"] == "risk" and c["id"] != "ai1" for c in checks)
        page_read = any(c["id"] == "ai2" and c["state"] == "clear" for c in checks)
        if only_model and page_read:
            label, conf = "Not a recognised site, no clear malicious behaviour", "medium"
            text = ("Nothing confirms that this is an established or official website, and the web address looks like phishing addresses to the "
                    "URL model. But the page itself was read and the page checks found no automatic download, no hidden or obfuscated script "
                    "and no fake login or payment form. This is not a guarantee: be careful with ads, pop-ups and redirects, and do not enter "
                    "passwords or payment details.")
        else:
            label, conf = "Suspicious: be careful", "medium"
            text = "Some warning signs were found but not enough to call the site malicious. Do not enter passwords or payment details unless you are sure it is the real site."
'''),
]


def main() -> int:
    if not TARGET.exists():
        print(f"Cannot find {TARGET}")
        return 1
    bak = TARGET.with_name(TARGET.name + ".bak")
    text = TARGET.read_text(encoding="utf-8")
    if MARK in text:
        print("The age-rule fix is already applied. Nothing to do.")
        return 0
    if OLD_MARK in text:                                   # the first version of this fix was applied earlier
        original = bak.read_text(encoding="utf-8") if bak.exists() else ""
        if not original or OLD_MARK in original:
            print("The first version of this fix is in detector.py, but its backup (detector.py.bak) is missing or is not the original.\n"
                  "Restore the original detector.py (git checkout or your own copy), then run this again.")
            return 1
        text = original
        print("Upgrading from the first version of this fix (starting again from the original in detector.py.bak).")
    bad = [i for i, (old, _new) in enumerate(EDITS, 1) if text.count(old) != 1]
    if bad:
        print("Nothing was changed. These pieces of detector.py were not found exactly once (the file was edited there): "
              + ", ".join(f"edit {i}" for i in bad) + ".\nSend the current detector.py section for those edits and they can be adjusted.")
        return 1
    if OLD_MARK not in TARGET.read_text(encoding="utf-8"):
        shutil.copyfile(TARGET, bak)                       # back up the untouched original (not when upgrading: it is already there)
    for old, new in EDITS:
        text = text.replace(old, new)
    TARGET.write_text(text, encoding="utf-8")
    print(f"Applied {len(EDITS)} edits to detector.py (backup: detector.py.bak). Restart the backend: python app.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
