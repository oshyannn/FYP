FYP update: site decisions, Saved URLs, public Detection Lists, admin threat list fixes
Copy every file to the same path inside D:\Desktop\FYP\ (overwrite). Folder layout in this zip = project layout.

BACKEND / AIDev (restart: cd Backend ; python app.py)
  AIDev\aidev\core\list_store.py, AIDev\aidev\detection\detector.py        admin-approved threats beat the whitelist; no hang when Supabase is down
  Backend\web\detector_sync.py, web_setup.py (registers all new blueprints, CORS now allows PUT)
  Backend\web\controllers\ + db_models\ :
      system_lists  (admin: manage whitelist/not_trusted/blacklist/adult_manual)
      site_rules    (user: always allow / always block a website)       -> table url_lists (already exists)
      saved_urls    (user: star / saved websites)                        -> table saved_urls (ALREADY CREATED in Supabase)
      lists_view    (everyone: read the lists the detector really uses)
      threats.py, submissions.py (refresh the detector after approve/remove)

EXTENSION (then chrome://extensions -> Reload)
  Extension\chrome\siterules.js (NEW), background.js (changed; diff in background.js.diff: cache 30 s, site rules gate),
  blocked.html, blocked.js (choices: this visit / 1 hour / until browser closes / always allow with confirmation),
  popup\* (built star + Site settings screen); ui\src\* = popup source (only needed if you rebuild with `node build.mjs`).

DESKTOP APP (restart npm run dev / rebuild)
  src\api.ts (api.put), electron\main.cjs (PUT + safebrowse://saved and ://sites),
  src\lib\sites.ts, src\pages\shared\SavedUrls.tsx, SiteSettings.tsx, DetectionLists.tsx,
  src\components\layout\nav.ts, src\pages\user\UserApp.tsx, src\pages\staff\StaffApp.tsx
  New sidebar items: User = Detection Lists, Saved URLs, Site settings; Employer/Admin = Detection Lists.

NOT tested in real Chrome/Electron (sandbox has none): please try
  1. open a flagged site -> warning -> pick "1 hour" -> reopen -> allowed; Site settings in popup -> "Restore the warning"
  2. "Always allow" needs the checkbox; then it appears in Desktop App > Site settings and can be removed
  3. Always block a site -> blocked page; Remove in Desktop App -> normal again
  4. star in popup -> Desktop App > Saved URLs
  5. any role > Detection Lists: check a domain, browse Trusted / Blocked / Threat feeds, search Restricted

Still to clean up by you (Supabase): delete from detection_lists where value='test-blocked-example.com';
  and revoke the two active translate.google.com test rows in global_urls.

ADDED (Detection Rules page, Employer + Admin sidebar):
  DesktopApp\src\pages\shared\SystemLists.tsx (NEW), src\components\layout\nav.ts, src\pages\staff\StaffApp.tsx (re-copy)
  Admin: add / switch off Whitelist, Not trusted, Blacklist, Restricted (manual) entries + "why is this site trusted?" lookup.
  Employer: same page, read-only. Uses the /api/staff/system-lists API already in the zip.

ADDED: optional "This page only" scope for front-page threat entries (default unchanged = whole site)
  Supabase: column global_urls.match_scope ('auto' | 'exact', default 'auto') ALREADY CREATED. All existing rows stay 'auto'.
  AIDev\aidev\core\list_store.py, AIDev\aidev\detection\detector.py (re-copy; works even before the column exists)
  Backend\web\controllers\threats.py, submissions.py, Backend\web\db_models\threats.py, submissions.py (re-copy)
     POST /api/staff/threats/<id>/review      + optional "match_scope" (admin only)
     PATCH /api/staff/threats/<id>/scope      admin: switch an active entry between whole site / this page only
     POST /api/staff/threat-submissions/<id>/review  + optional "match_scope"
  DesktopApp\src\components\ScopeChoice.tsx (NEW), src\lib\threats.ts, src\pages\shared\ThreatUrlList.tsx,
     src\pages\staff\approval\ThreatSubmissions.tsx
     Admin only, front-page URLs only: the approve dialog offers "Whole site (default)" / "This page only";
     active rows get a "Scope" button; the detail window shows "Blocks: Whole site / This page only".
  To block a whole site on purpose in "page only" mode: Detection Rules > Blacklist.
