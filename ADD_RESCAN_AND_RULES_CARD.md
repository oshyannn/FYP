# Re-scan + separate "Rule-based page checks" card — install

Extract this zip INTO your FYP folder (merge). Delete this file afterwards. No database change.

## What changes
1. Detailed Analysis: the five bars under AI 2 (Fake login page, Fake bank / payment page, ...) are now their OWN card:
   "5. Rule-based page checks", marked RULES · NOT AI, with a dashed border and no percentage bars. Each row says
   Nothing found / Weak signs / Some signs / Strong signs. The AI 2 card keeps only the model's probability and says it is the
   model's overall estimate (the model does not list reasons). Cards are renumbered: 6 = AI Combined, 7 = Final Result.
2. Re-scan: a "Re-scan" button (top and bottom) on Detailed Analysis. It scans the same address again, forgets the remembered
   answers for THAT address first (the finished verdict, the PhishTank answer, the Safe Browsing answer), and shows the new result in
   place. Each Re-scan adds a new entry to Detection History (type Manual).
3. "This result is incomplete" banner: shown when a source could not answer (PhishTank lookup failed, page could not be read by AI 2 ...).
   It names the sources and points to Re-scan.

## Files
NEW   Backend/scripts/enable_rescan.py                  one-time: edits detector.py + scans.py together (all or nothing)
EDIT  DesktopApp/src/pages/user/scan/DetailedAnalysis.tsx   (replace; changes: header, banner, AI 2 card, rule card, numbering, buttons)
EDIT  DesktopApp/src/pages/user/UserApp.tsx             (replace; 2 added props on <DetailedAnalysis>, marked "added")
  UserApp.tsx here already contains the Browser Activity changes from FYP_browser_activity.zip. If you did NOT install that zip,
  do not overwrite UserApp.tsx: add the two marked props by hand.
If you changed either file locally since the last commit, compare before overwriting.

## Steps
1. cd Backend ; python -m scripts.enable_rescan
   - adds forget(url) at the end of AIDev/aidev/detection/detector.py and 3 lines in Backend/web/controllers/scans.py
   - backups: detector.py.before_rescan.bak and scans.py.before_rescan.bak; safe to run twice
   - works whether or not you applied enable_optional_ai before
2. Restart: python app.py     then the desktop app: npm run dev
3. Open any scan -> Detailed Analysis -> try Re-scan. To test the banner: stop your internet for a moment, scan a new address, then
   reconnect and press Re-scan.

## Not included (still to do)
- Re-scan buttons on Detection History / Browser Activity rows (the Detailed Analysis page is the one place for now).
- The extension popup does not have a Re-scan button yet.
- Fixing the false "Fake login page" signs on real sign-in pages (needs AIDev changes: page_threats.py / content_features.py).

## file_structure.md — add these
Backend/scripts: enable_rescan.py (one-time: POST /api/scans accepts "fresh"; adds forget() to detector.py)
Section "Scanning": POST /api/scans accepts {"url", "fresh"}; fresh=true forgets the cached answers for that address first
