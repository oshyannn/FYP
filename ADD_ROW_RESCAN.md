# Re-scan on every row (Detection History + Browser Activity) — install

Extract this zip INTO your FYP folder (merge). Delete this file afterwards. Frontend only: nothing in the backend or database changes.

## What changes
A "Re-scan" link next to View / Delete in Detection History, and next to "View Details in SafeBrowse" in Browser Activity.
It scans that address again (with "fresh": true, so the detector forgets what it remembered for it) and opens the new result.
Each Re-scan adds a new entry to Detection History (type Manual). Back returns to the list you came from.
Needs FYP_rescan_rules_card.zip (enable_rescan) to make the detector forget the old answers; without it the button still works
but the detector may answer from its short memory (up to an hour).

## Files (both replaced; changes are marked "added")
DesktopApp/src/pages/user/scan/DetectionHistory.tsx
DesktopApp/src/pages/user/activity/BrowserActivity.tsx
If you changed either file locally since the last commit, compare before overwriting.
BrowserActivity.tsx already has the Browser Activity page from FYP_browser_activity.zip.

## Steps
Replace the two files, then npm run dev. Try Re-scan on a row in each list.
