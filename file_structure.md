# FYP: file structure (read this instead of browsing the repo)

Self-contained map of the workspace so another AI (or teammate) can work on it without opening GitHub.
**Keep it current:** when a file or folder is added, moved or deleted, update the tree and tables in the same commit.
Layout version: 2026-11-04 (four parts; URL scanner, Feedback, Threat URL list, Employer verification, dashboards and profile, Whitelist + URL Approval, User Management + Activity Logs, and now staff accounts by invitation with administrator approvals; the desktop app has a role-based shell for user / employer / admin).

## 1. What the project is

**SafeBrowse / Real-Time Malicious URL Detection System** (course BMCS3403, repo `oshyannn/FYP`). Four parts:

1. **DesktopApp**: Electron + React + Vite app. Users register/log in, an administrator invites staff (employers and administrators) by email and they activate the account themselves, and a logged-in user generates a **pairing code** for the browser extension and can **scan URLs** (scan result, detailed analysis, detection history). After login a sidebar shell shows the screens of the role: **user** (dashboard, scanner, history, threat list, whitelist, feedback, profile), **employer** (dashboard, threat URL review + submit, URL approval, user management for users only, feedback, their own activity logs) and **admin** (the same plus employer verification, the whitelist for everyone, user management of users and employers, and the activity logs of admins and employers).
2. **Extension**: Chrome Manifest V3 extension. Checks every navigation with the backend, shows block/"checking" pages, pauses risky downloads. Popup is React (source in `Extension/ui`, build output committed in `Extension/chrome/popup`).
3. **Backend**: Flask. `POST /analyze` (`{"url": ...}` -> verdict), plus the account API for the desktop app and extension pairing (`/api/auth/*`, `/api/staff/*`, `/api/extension/*`, `/api/me*`), the scan API for the desktop URL scanner (`web/controllers/scans.py`), the feedback API (`feedback.py`), the threat URL list and its review (`threats.py`), employer verification (`employers.py`), the dashboards (`dashboard.py`), trusted websites and whitelist requests (`whitelist.py`), employer threat submissions (`submissions.py`), account management for admins (`user_admin.py`) the admin audit trail (`activity.py`) and staff invitations with administrator approvals (`staff_accounts.py`) on Postgres (Supabase).
4. **AIDev**: the detection engine (Python package `aidev`), the data, the trained models and the training pipeline. Backend imports it.

Flow: `Extension / DesktopApp  --HTTP-->  Backend/app.py  --import-->  AIDev aidev.detection.detector.analyze(url)`.

## 2. Repository tree (in git)

```
FYP/
├── README.md                    Human quick start
├── file_structure.md            THIS FILE
├── setup_envs.py                Creates AIDev/.venv + Backend/.venv, installs requirements, runs npm install (stdlib only)
├── .gitignore
├── DesktopApp/                  Electron + React + Vite desktop app (own package.json, own node_modules)
│   ├── electron/main.cjs, preload.cjs      Electron main process (API_BASE from env SAFEBROWSE_API, default http://127.0.0.1:5000).
│   │                                       main.cjs only forwards paths that match PATH_OK; preload.cjs exposes window.sb to the page
│   ├── src/                                React + Tailwind
│   │   ├── App.tsx, api.ts, types.ts, main.tsx, index.css   App.tsx picks the screen by login state and role (UserApp or StaffApp)
│   │   ├── components/                     shared UI: AuthShell, Field, Logo, ui; Badge.tsx = general status badge; StatusBadge.tsx = verdict badge (scan pages);
│   │   │   │                               Modal.tsx, ConfirmDialog.tsx, Pager.tsx = building blocks of the review / approval screens
│   │   │   ├── layout/                     AppLayout.tsx (sidebar shell), nav.ts (menu items per role)
│   │   │   └── feedback/                   Badge.tsx, ReplyBox.tsx, ThreadView.tsx (shared by the user and staff feedback screens)
│   │   ├── lib/analysis.ts                 helpers for scan / analysis results (the only file that reads the detector's result fields)
│   │   ├── lib/feedback.ts                 feedback types, labels, status tones, PATCH helper
│   │   ├── lib/dashboard.ts, threats.ts    dashboard figures; threat URL labels and types
│   │   ├── lib/approvals.ts                whitelist requests and threat submissions: types, labels, score colours, dates
│   │   ├── lib/admin.ts                    User Management and Activity Logs: types, status / role / action labels, log date format
│   │   └── pages/
│   │       ├── auth/                       UserLogin, Register, VerifyEmail, ForgotPassword, ResetPassword, StaffLogin, AcceptInvite (an invited employer / admin activates the account)
│   │       ├── shared/                     Profile.tsx; ThreatUrlList.tsx (user / employer / admin; employers also get "Submit Threat URL" and "My Submissions");
│   │       │                               Whitelist.tsx ("Trusted Websites": a user's own list, a new site is a request that an employer / admin approves;
│   │       │                               for an admin it is the list for every user, added directly)
│   │       ├── StaffFeedback.tsx           employer / admin: list, open, reply, set status, close feedback
│   │       ├── staff/                      StaffApp.tsx (menu + routing for employer and admin), StaffDashboard.tsx, EmployerVerification.tsx (admin only)
│   │       │   ├── approval/               UrlApproval.tsx (tabs), WhitelistRequests.tsx (employer + admin), ThreatSubmissions.tsx (admin only)
│   │       │   ├── submissions/            SubmitThreatModal.tsx, MySubmissions.tsx (employer; shown inside the Threat URL List)
│   │       │   ├── users/                  UserManagement.tsx (tabs: Accounts, Deleted; admin also Invitations, Approvals, Create Account), ManageUserModal.tsx (view / edit name / activate / deactivate / delete / password reset email; for another admin: send a request),
│   │       │   │                           CreateAccountModal.tsx (invite an employer or admin), Invitations.tsx (status, accepted when, revoke), Approvals.tsx (decide what another admin started)
│   │       │   └── logs/                   ActivityLogs.tsx (admin: admins + employers, filter and search; employer: only their own actions)
│   │       └── user/                       logged-in user area
│   │           ├── UserApp.tsx             menu + routing for normal users
│   │           ├── Dashboard.tsx           user dashboard (recent scans, figures)
│   │           ├── feedback/Feedback.tsx   user: submit / attach scan / edit / follow-up / status / search
│   │           └── scan/                   UrlScanner.tsx (enter URL), ScanResult.tsx (verdict),
│   │                                       DetailedAnalysis.tsx (signals/details), DetectionHistory.tsx (past scans)
│   ├── index.html, vite.config.ts (dev port 5173), tsconfig.json, package.json, package-lock.json
│   └── README.md, .gitignore
├── AIDev/                       Python. Run commands from here: python -m aidev.<folder>.<module>
│   ├── aidev/                   the package
│   │   ├── core/                common.py (all paths + list helpers), features.py (29 URL features, FEATURE_VERSION)
│   │   ├── detection/           detector.py (analyze), predict.py (URL model), predict_content.py (page model),
│   │   │                        content_features.py, lookalike.py, phishtank.py, safebrowsing.py, rdap.py, pagefetch.py
│   │   ├── pipeline/            feeds, import_phishtank, import_labeled, import_adult, import_phreshphish, export_history,
│   │   │                        crawl_pages, build_dataset, train, train_content
│   │   ├── evaluation/          eval_fresh, eval_lookalike, check_sources
│   │   └── tools/               try_urls, testai, test_ai, test_samples, content_testsite, verify_server (+verify.html),
│   │                            checking, test, verify_fix (PhishTank diagnostics)
│   ├── lists/                   whitelist, blacklist, not_trusted, protected_domains, shared_hosts, trusted_prefixes, trusted_suffixes, adult_manual (.txt)
│   ├── data/                    NOT in git (README.md explains how to rebuild)
│   ├── models/                  model_metrics.json, model_content_metrics.json, backup_20261019/ (.joblib files are NOT in git, except one old backup)
│   ├── experiments/             exp_*.json metrics of content-model experiments (their .joblib are NOT in git)
│   ├── docs/ML_HANDOFF.md       data, features, metrics, detector rules, known weaknesses; docs/archive/ = outdated notes
│   ├── requirements.txt         = runtime + training extras;  requirements-runtime.txt = what the live detector needs (shared with Backend)
│   ├── .env.example             PHISHTANK_API_KEY, GOOGLE_SAFE_BROWSING_API_KEY, BLOCK_ADULT, CONTENT_CHECK
│   └── README.md
├── Backend/                     Python. Run from here: python app.py
│   ├── app.py                   ENTRY POINT. Adds ../AIDev to sys.path, defines /analyze, mounts the account API when configured
│   ├── config.py                every setting, from environment variables (Backend/.env)
│   ├── web/                     web_setup.py (registers every blueprint), extensions.py (rate limiter), guards.py (Bearer auth, role checks), security.py (argon2, tokens),
│   │   │                        mailer.py, db.py (Postgres pool)
│   │   ├── controllers/         api_auth.py (login, register, me, profile, pairing), verify_pages.py (email verification page),
│   │   │                        scans.py (URL scan + history API; a trusted website is shown as safe unless the detector found it malicious),
│   │   │                        common.py (shared controller helpers),
│   │   │                        feedback.py (feedback API: user /api/feedback*, staff /api/staff/feedback*),
│   │   │                        threats.py (threat URL list + review), employers.py (admin: employer applications), dashboard.py (dashboard figures),
│   │   │                        whitelist.py (trusted websites /api/whitelist*, whitelist requests /api/staff/whitelist-requests*),
│   │   │                        submissions.py (employer threat submissions /api/staff/threat-submissions*),
│   │   │                        user_admin.py (employer + admin: accounts /api/staff/users*), activity.py (audit trail /api/staff/activity-logs: admin sees all, employer only their own),
│   │   │                        staff_accounts.py (admin: invitations /api/staff/invitations*, changes to another admin /api/staff/admin-changes*, /api/staff/approvals; anyone: /api/staff/accept-invite)
│   │   └── db_models/           users.py, sessions.py, tokens.py, audit.py, scans.py, feedback.py, threats.py, employers.py, stats.py, staff_accounts.py,
│   │                            whitelist.py, submissions.py, user_admin.py, activity.py  (database tables; NOT machine-learning models)
│   ├── scripts/staff_admin.py   create the first admin (python -m scripts.staff_admin create-admin ...); reset-password EMAIL as a last resort. Employers are approved in the desktop app now
│   ├── scripts/enable_feedback.py   one-time: registers the feedback blueprint in web/web_setup.py (python -m scripts.enable_feedback)
│   ├── scripts/setup_url_approval.py   one-time: creates whitelist_requests, whitelist_entries, threat_submissions (python -m scripts.setup_url_approval)
│   ├── scripts/setup_user_management.py   one-time check: the label for a deactivated account, and the audit log's enum labels if its columns are enums (python -m scripts.setup_user_management)
│   ├── scripts/setup_staff_accounts.py   one-time: creates staff_invitations and admin_change_requests (python -m scripts.setup_staff_accounts)
│   ├── requirements.txt         includes ../AIDev/requirements-runtime.txt
│   ├── .env.example             APP_ENV, SECRET_KEY, DATABASE_URL, BASE_URL, GMAIL_*, ALLOWED_EMAIL_DOMAINS, REQUIRE_AUTH_FOR_ANALYZE, CORS_ORIGINS
│   └── README.md
└── Extension/
    ├── chrome/                  Load unpacked in Chrome. manifest.json, background.js (service worker, API_BASE), content.js,
    │                            blocked/checking/prompt .html+.js, pages/ui.css, popup/ (BUILT React popup), icons/, README.md
    ├── ui/                      React/Tailwind popup source: src/, build.mjs (writes ../chrome/popup), package.json
    └── testsite/                local test pages + server.py (port 8000) + make_files.py
```

Not in git but present on the owner's machine: `AIDev/.env`, `Backend/.env`, `AIDev/.venv`, `Backend/.venv`, `AIDev/data/**` (~500 MB: feeds, datasets, `pages/html/*.html.gz`),
`AIDev/models/*.joblib` (URL model ~720 MB, content model ~60 MB), `AIDev/experiments/*.joblib`, `DesktopApp/node_modules`.

## 3. How the pieces connect

```
Extension/chrome/background.js ──POST /analyze (Bearer token; look-ups that are not saved)──▶ Backend/app.py ──▶ aidev.detection.detector.analyze(url)
Extension/chrome/background.js ──POST /api/scans (Bearer token; every page check is saved to the account)──▶ Backend/web/controllers/scans.py ──▶ Postgres ──▶ DesktopApp Detection History
Extension popup "See more in app" ──safebrowse://history──▶ DesktopApp/electron/main.cjs (protocol link) ──▶ pages/user/UserApp.tsx (takePendingPage / onOpenPage)
DesktopApp (Electron) ──/api/auth, /api/staff, /api/me, /api/extension/pairing-code──▶ Backend/web/controllers/api_auth.py ──▶ web/db_models ──▶ Postgres
DesktopApp pages/user/scan ──scan requests / history──▶ Backend/web/controllers/scans.py ──▶ web/db_models/scans.py ──▶ Postgres
                           scans.py ──▶ aidev.detection.detector.analyze(url); suspicious / malicious results also go to the shared threat list (global_urls, status pending_review)
                           scans.py ──▶ web/db_models/whitelist.py trusted_scope(user, host): a trusted website is shown as safe, a malicious verdict is never overridden
DesktopApp pages/user/feedback + pages/StaffFeedback ──/api/feedback, /api/staff/feedback──▶ Backend/web/controllers/feedback.py ──▶ web/db_models/feedback.py ──▶ Postgres (public.feedback)
DesktopApp pages/shared/ThreatUrlList ──/api/threats, /api/staff/threats/<id>/review──▶ Backend/web/controllers/threats.py ──▶ web/db_models/threats.py
DesktopApp pages/staff/EmployerVerification ──/api/admin/employers*──▶ Backend/web/controllers/employers.py (admin only)
DesktopApp pages/shared/Whitelist ──/api/whitelist──▶ Backend/web/controllers/whitelist.py ──▶ web/db_models/whitelist.py ──▶ Postgres (whitelist_entries, whitelist_requests)
DesktopApp pages/staff/approval ──/api/staff/whitelist-requests──▶ whitelist.py            (employer + admin review user requests; approval trusts the site for the requester only)
                                ──/api/staff/threat-submissions──▶ submissions.py ──▶ Postgres (threat_submissions; global_urls when approved)   (admin only)
DesktopApp pages/staff/submissions ──/api/staff/threat-submissions, /mine──▶ submissions.py   (employer submits a threat URL, follows its status)
DesktopApp pages/staff/users ──/api/staff/users*──▶ Backend/web/controllers/user_admin.py ──▶ web/db_models/user_admin.py ──▶ Postgres (users); the model limits by role, deactivating or deleting also ends every session; "password-reset" emails the 6-digit reset code (tokens + mailer)
DesktopApp pages/staff/logs ──/api/staff/activity-logs──▶ Backend/web/controllers/activity.py ──▶ web/db_models/activity.py ──▶ Postgres (activity_logs, filled by web/db_models/audit.py); an employer is always limited to their own id
DesktopApp pages/staff/users (admin) ──/api/staff/invitations*, /api/staff/admin-changes*, /api/staff/approvals──▶ Backend/web/controllers/staff_accounts.py ──▶ web/db_models/staff_accounts.py ──▶ Postgres (staff_invitations, admin_change_requests); an invitation email goes out through web/mailer.py
DesktopApp pages/auth/AcceptInvite ──POST /api/staff/accept-invite (nobody signed in)──▶ staff_accounts.py: code (+ PIN for an admin) checked, then the account is created with the sanctioned role write (app.privileged_role_write) and the person's own password
Extension popup ──/api/extension/pair (code from the desktop app)──▶ Backend  ──▶ token kept in chrome.storage.local

aidev.detection.detector  reads  AIDev/lists/*.txt, AIDev/data/tranco_top.txt, feeds_urls.txt, adult_domains.txt
                          uses   predict.py (core/features.py + models/model.joblib), predict_content.py (models/model_content.joblib),
                                 lookalike.py, phishtank.py, safebrowsing.py, rdap.py
AIDev/aidev/pipeline: feeds, import_* ─▶ data/* ─▶ build_dataset ─▶ data/dataset.csv ─▶ train ─▶ models/model.joblib
                      crawl_pages / import_phreshphish ─▶ data/pages/ ─▶ train_content ─▶ models/model_content.joblib
```

Dependency direction: `aidev.core` <- `aidev.detection` <- (`aidev.pipeline`, `aidev.evaluation`, `aidev.tools`) <- `Backend/app.py`.
`aidev` never imports Backend. Backend imports `aidev.detection.detector` in `app.py`, `web/controllers/scans.py` and `web/controllers/whitelist.py`, and `aidev.core.features` in `scans.py`, `whitelist.py` and `submissions.py`. Imports are absolute: `from aidev.core.common import DATA`, `from web.guards import auth_required`, `import config`.
Every path inside AIDev comes from `aidev/core/common.py` (`ROOT` = the `AIDev/` folder; `DATA`, `LISTS`, `MODELS`, `EXPERIMENTS`, `MODEL_PATH`, ...). Do not hard-code paths elsewhere.

## 4. Environments and running things

Each Python folder has its own virtual environment; `python setup_envs.py` creates them (Python 3.11+, tested on 3.13).

| Part | Environment | Run (from that folder) |
|---|---|---|
| AIDev | `AIDev/.venv` from `AIDev/requirements.txt` | `python -m aidev.tools.try_urls URL`, `python -m aidev.pipeline.train`, ... |
| Backend | `Backend/.venv` from `Backend/requirements.txt` | `python app.py`  (http://127.0.0.1:5000) |
| DesktopApp | `npm ci` | `npm run dev` (Vite on 5173 + Electron) or `npm start` |
| Extension/ui | `npm install` | `npm run build` (rewrites `Extension/chrome/popup`) |
| Extension/chrome | none | Chrome > Extensions > Developer mode > Load unpacked |

Secrets: `AIDev/.env` (PhishTank, Safe Browsing, switches) and `Backend/.env` (account/database/mail). Backend also reads `AIDev/.env` because it imports the detector.
Never run `python AIDev/aidev/...py` directly; use `python -m aidev.<folder>.<module>` from `AIDev/` so imports resolve.

## 5. Rules and invariants (do not break these)

- `aidev/core/features.py` is the only place URL features are computed; after any change bump `FEATURE_VERSION` and retrain (`predict.py` refuses mismatched models).
- Training and serving must have the **same** `tldextract` situation (installed in both venvs) and the **same scikit-learn** (pinned 1.9.1 in `AIDev/requirements-runtime.txt`; all existing models were trained with it). Change versions only together with a retrain.
- `predict()` returning `None` means "no opinion", never "safe". The URL model alone can raise Suspicious, never Malicious. No "Safe" verdict without positive evidence (whitelist, trusted prefix/suffix).
- A database whitelist entry (`whitelist_entries`) is such positive evidence, applied in `web/controllers/scans.py` and never over a malicious verdict. A user's own entry only exists after an employer / admin approved the request; an admin can add global entries directly.
- Secrets only in `.env` files; never commit them, `AIDev/data/`, `*.joblib`, or `benign_extra.csv` (your browsing history).
- `Backend/web/db_models/` are database tables; ML models are `AIDev/models/*.joblib`.
- `API_BASE` is duplicated in `Extension/chrome/background.js` and `Extension/ui/src/config.ts`; keep them equal.
- `tools/` and `scripts/` are manual helpers; nothing in production imports them.
- Approval chain: user -> employer / admin (whitelist requests), employer -> admin (threat submissions). Only an admin reviews employer applications and threat submissions; employers cannot review their own submissions.
- User Management: an admin sees users, employers and admins and changes users and employers directly; for ANOTHER admin it can only request a deactivation, activation or deletion and a THIRD admin (not the requester, not that account) approves (`admin_change_requests`; at least one active admin must remain). An employer sees and changes users only and cannot delete. Nobody changes their own account there. The rules live in `VIEW_ROLES` / `ACT_ROLES` in `db_models/user_admin.py` and every account JSON carries `actions` for the screen. A deactivated account is any status other than `active` / `pending` / `deleted`; deactivating or deleting ends all its sessions. A `pending` account can be deactivated or deleted, never activated from there. Delete is soft (`deleted`, read-only, on its own tab); an account that never verified its email is deleted for good if the database allows it, which frees the address.
- Staff accounts are created only by invitation (`staff_invitations`): the address is checked BEFORE anything is emailed (an address that already has an account or an open invitation is refused). An employer invitation is emailed at once. An admin invitation waits for ANOTHER admin to approve it and has a 6-digit PIN, shown to the inviter once and never emailed; accepting needs the emailed code AND the PIN. The invited person sets their own password; the account is created only at that moment, with the sanctioned `app.privileged_role_write`. Codes expire after 24 hours, are single-use and lock after `CODE_MAX_ATTEMPTS` wrong tries. Employer self sign-up (`/api/staff/request-access`) is closed and answers 410; existing applications can still be decided under Employer Verification.
- Activity Logs show only what staff did (`STAFF_ACTIONS` in `db_models/activity.py`), never logins. An admin sees admins and employers (filter + search by name or email); an employer only their own, and the id comes from the login, never from the request. A new staff action must call `audit.log(...)` with an action name listed there and readable ids or an email in `details`.
- Only suspicious / malicious scans reach the shared threat list (`global_urls`, status `pending_review`); safe and unknown scans stay in the user's own history. Query strings are removed before a URL is stored in the shared list or in a submission.
- `DesktopApp/electron/main.cjs` only forwards paths that match `PATH_OK` (letters, digits, `/ _ -` and an optional simple query string). A new endpoint the desktop app calls must match it and be registered in `Backend/web/web_setup.py`.
- `DesktopApp/src/lib/analysis.ts` is the one place that reads the detector's result fields; screens read through it.
- The new tables (`whitelist_*`, `threat_submissions`) have row level security on and no policies: only the backend (database owner) reads or writes them.

## 6. Where to change what

| Task | Look in |
|---|---|
| Change how a verdict is decided / add a signal | `AIDev/aidev/detection/detector.py` (+ new module in `detection/`) |
| Add or change a URL feature | `AIDev/aidev/core/features.py`, bump `FEATURE_VERSION`, run `aidev.pipeline.train` |
| Page-content feature | `AIDev/aidev/detection/content_features.py`, then `aidev.pipeline.train_content` |
| Trust or block a domain by hand (system-wide, in git) | `AIDev/lists/whitelist.txt`, `blacklist.txt`, `not_trusted.txt`, `protected_domains.txt` |
| New training data source | new `AIDev/aidev/pipeline/import_*.py` writing to `AIDev/data/`, read by `build_dataset.py` |
| Account / login / pairing / profile API | `Backend/web/controllers/api_auth.py`, `Backend/web/db_models/*`, `Backend/web/security.py` |
| Settings | `Backend/config.py` + `Backend/.env.example` (account side), `AIDev/.env.example` (detector side) |
| Extension behaviour | `Extension/chrome/background.js` and the matching page; popup UI in `Extension/ui/src` |
| URL scanner screens (scan, result, detailed analysis, history) | `DesktopApp/src/pages/user/scan/*`, `DesktopApp/src/lib/analysis.ts`, `DesktopApp/src/components/StatusBadge.tsx` |
| Scan / history API and storage | `Backend/web/controllers/scans.py`, `Backend/web/db_models/scans.py` |
| Feedback (submit, attach scan, edit, reply, status, close, search) | `Backend/web/controllers/feedback.py`, `Backend/web/db_models/feedback.py`; screens `DesktopApp/src/pages/user/feedback/Feedback.tsx`, `DesktopApp/src/pages/StaffFeedback.tsx`, shared `DesktopApp/src/components/feedback/`, `DesktopApp/src/lib/feedback.ts` |
| Whitelist (Trusted Websites) | `Backend/web/controllers/whitelist.py`, `Backend/web/db_models/whitelist.py`; screen `DesktopApp/src/pages/shared/Whitelist.tsx`; how it changes a scan: `_apply_whitelist` in `controllers/scans.py` |
| URL Approval (whitelist requests, threat submissions) | `Backend/web/controllers/whitelist.py` (requests), `submissions.py` (threat submissions) + `db_models/*`; screens `DesktopApp/src/pages/staff/approval/*`; employer side `pages/staff/submissions/*` inside `pages/shared/ThreatUrlList.tsx`; labels in `lib/approvals.ts` |
| User Management (list, view, edit name, activate / deactivate, delete, password reset email) | `Backend/web/controllers/user_admin.py`, `Backend/web/db_models/user_admin.py` (who may do what: `VIEW_ROLES` / `ACT_ROLES`); screens `DesktopApp/src/pages/staff/users/*`, labels in `lib/admin.ts`; last-resort password reset: `python -m scripts.staff_admin reset-password EMAIL` |
| Activity Logs (audit trail) | `Backend/web/controllers/activity.py`, `Backend/web/db_models/activity.py` (what counts as a staff action: `STAFF_ACTIONS`); screen `DesktopApp/src/pages/staff/logs/ActivityLogs.tsx`; action names in `lib/admin.ts`; events are written by `audit.log` in `web/db_models/audit.py` |
| Create employer / admin accounts, invitations, approvals | `Backend/web/controllers/staff_accounts.py`, `Backend/web/db_models/staff_accounts.py`; screens `DesktopApp/src/pages/staff/users/{CreateAccountModal,Invitations,Approvals}.tsx`, activation screen `pages/auth/AcceptInvite.tsx`; invitation email: `send_staff_invite` in `web/mailer.py` |
| Threat URL list and its review | `Backend/web/controllers/threats.py`, `Backend/web/db_models/threats.py`; screen `DesktopApp/src/pages/shared/ThreatUrlList.tsx`, labels in `lib/threats.ts` |
| Employer verification (admin) | `Backend/web/controllers/employers.py`, `Backend/web/db_models/employers.py`; screen `DesktopApp/src/pages/staff/EmployerVerification.tsx` |
| Dashboards | `Backend/web/controllers/dashboard.py`, `Backend/web/db_models/stats.py`; screens `pages/user/Dashboard.tsx`, `pages/staff/StaffDashboard.tsx`, figures in `lib/dashboard.ts` |
| Menu items per role / sidebar | `DesktopApp/src/components/layout/nav.ts`, `AppLayout.tsx`; routing in `pages/user/UserApp.tsx` and `pages/staff/StaffApp.tsx` |
| Add a new API endpoint the desktop app calls | new route in a controller, register the blueprint in `Backend/web/web_setup.py`, check `PATH_OK` in `DesktopApp/electron/main.cjs` |
| Create / change database tables for a feature | a one-time script in `Backend/scripts/` (see `setup_url_approval.py`): only creates what is missing, checks first, one transaction |
| Desktop screens in general | `DesktopApp/src/pages`, API calls in `DesktopApp/src/api.ts`, Electron in `DesktopApp/electron/main.cjs` |
| ML numbers, data sources, known weaknesses | `AIDev/docs/ML_HANDOFF.md` |

## 7. Status (2026-11-04)

URL model: Random Forest, ROC-AUC about 0.87, recall about 67% at 0.5. Content model trained on page features; no trusted accuracy number yet (see `AIDev/docs/ML_HANDOFF.md`).
Extension pairs with the desktop app. Scan history is NOT kept in the browser: it is saved to the account and read in the desktop app (login required). Settings stay in `chrome.storage.local` behind `Extension/ui/src/store.ts` (Supabase later).
Not built yet (menu item marked "Soon"): Browser Activity. The whitelist does not yet apply to `POST /analyze` (only to `POST /api/scans`).
Open items: end-to-end re-test after the latest retrain, a hand-labelled test set, a time-based evaluation. The URL model file is ~720 MB (loaded at every Backend start).
