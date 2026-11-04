# Browser Activity (user) — install

Extract this zip INTO your FYP folder (merge folders). Delete this file afterwards.

## New files (nothing is overwritten)
Backend/web/controllers/browser_activity.py      GET /api/activity
Backend/web/db_models/browser_activity.py
Backend/scripts/enable_browser_activity.py       one-time: registers the blueprint in web/web_setup.py
DesktopApp/src/pages/user/activity/BrowserActivity.tsx

## 2 files that are replaced (differences are marked "added" / "changed")
DesktopApp/src/pages/user/UserApp.tsx            "activity" page + details opened from it return to it
DesktopApp/src/components/layout/nav.ts          Browser Activity: ready:true
  NOTE: this nav.ts also has User Management + Activity Logs (admin) set to ready:true, i.e. it matches the
  earlier FYP_admin_pages.zip. If you did NOT install that zip, those two admin items will open the dashboard;
  in that case change only the one "Browser Activity" line by hand instead of overwriting.
If you changed either file locally since the last commit, compare before overwriting.

## Steps
1. cd Backend ; python -m scripts.enable_browser_activity      (adds 2 lines to web_setup.py; safe to run twice)
2. Restart: python app.py
3. Desktop app: npm run dev -> log in as a normal user -> Browser Activity
No database change (reads public.detection_history and public.sessions). main.cjs needs no change.

## Behaviour
- Shows the pages the paired Chrome extension checked (scan type auto / redirect), newest first, latest 30,
  refreshing every 5 s (Pause / Resume). Status filter: Safe / Suspicious / Malicious / Unknown.
- Badge: Extension Connected (called the server in the last 10 min) / Idle (paired, quiet) / Not Connected.
- "View Details in SafeBrowse" opens the normal Detailed Analysis page; Back returns to Browser Activity.
- Manual scans from the desktop app are not listed here (see Detection History).

## file_structure.md — add these
Tree, Backend/web/controllers: browser_activity.py (GET /api/activity)
Tree, Backend/web/db_models: browser_activity.py
Tree, Backend/scripts: enable_browser_activity.py (one-time: registers browser_activity in web/web_setup.py)
Tree, DesktopApp/src/pages/user/activity: BrowserActivity.tsx
Section 6: "Browser activity (user)" -> controllers/browser_activity.py, db_models/browser_activity.py, pages/user/activity/BrowserActivity.tsx
Section 7: remove "Browser Activity" from the "Not built yet" list
