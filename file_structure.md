# FYP: file structure (read this instead of browsing the repo)

Self-contained map of the workspace so another AI (or teammate) can work on it without opening GitHub.
**Keep it current:** when a file or folder is added, moved or deleted, update the tree and tables in the same commit.
Layout version: 2026-10-29 (four parts; DesktopApp URL scanner area `pages/user/` + Backend scan API + Feedback module added).

## 1. What the project is

**SafeBrowse / Real-Time Malicious URL Detection System** (course BMCS3403, repo `oshyannn/FYP`). Four parts:

1. **DesktopApp**: Electron + React + Vite app. Users register/log in, staff request access, and a logged-in user generates a **pairing code** for the browser extension and can **scan URLs** (scan result, detailed analysis, detection history).
2. **Extension**: Chrome Manifest V3 extension. Checks every navigation with the backend, shows block/"checking" pages, pauses risky downloads. Popup is React (source in `Extension/ui`, build output committed in `Extension/chrome/popup`).
3. **Backend**: Flask. `POST /analyze` (`{"url": ...}` -> verdict), plus the account API for the desktop app and extension pairing (`/api/auth/*`, `/api/staff/*`, `/api/extension/*`), the scan API for the desktop URL scanner (`web/controllers/scans.py`) and the feedback API (`web/controllers/feedback.py`) on Postgres (Supabase).
4. **AIDev**: the detection engine (Python package `aidev`), the data, the trained models and the training pipeline. Backend imports it.

Flow: `Extension / DesktopApp  --HTTP-->  Backend/app.py  --import-->  AIDev aidev.detection.detector.analyze(url)`.

## 2. Repository tree (in git)

```
FYP/
├── README.md                    Human quick start
├── file_structure.md            THIS FILE
├── setup_envs.py                Creates AIDev/.venv + Backend/.venv, installs requirements, runs npm install (stdlib only)
├── .gitignore
├── DesktopApp/                  Electron + React + Vite desktop app (own package.json, own node_modules). Moved in unchanged
│   ├── electron/main.cjs, preload.cjs      Electron main process (API_BASE from env SAFEBROWSE_API, default http://127.0.0.1:5000)
│   ├── src/                                React: App.tsx, api.ts, types.ts
│   │   ├── components/                     shared UI; StatusBadge.tsx = verdict badge (used by the scan pages)
│   │   │   └── feedback/                   Badge.tsx, ReplyBox.tsx, ThreadView.tsx (shared by the user and staff feedback screens)
│   │   ├── lib/analysis.ts                 helpers for scan / analysis results
│   │   ├── lib/feedback.ts                 feedback types, labels, status tones, PATCH helper
│   │   └── pages/                          Login, Register, VerifyEmail, ResetPassword, Staff*, Home
│   │       ├── StaffFeedback.tsx           employer / admin: list, open, reply, set status, close feedback
│   │       └── user/                       logged-in user area
│   │           ├── feedback/Feedback.tsx   user: submit / attach scan / edit / follow-up / status / search
│   │           ├── ScanApp.tsx             container of the scanner section
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
│   ├── web/                     web_setup.py, extensions.py (rate limiter), guards.py (Bearer auth), security.py (argon2, tokens),
│   │   │                        mailer.py, db.py (Postgres pool)
│   │   ├── controllers/         api_auth.py (JSON API), verify_pages.py (email verification page),
│   │   │                        scans.py (URL scan + history API for the desktop app), common.py (shared controller helpers),
│   │   │                        feedback.py (feedback API: user /api/feedback*, staff /api/staff/feedback*)
│   │   └── db_models/           users.py, sessions.py, tokens.py, audit.py, scans.py, feedback.py  (database tables; NOT machine-learning models)
│   ├── scripts/staff_admin.py   create first admin / approve employers  (python -m scripts.staff_admin ...)
│   ├── scripts/enable_feedback.py   one-time: registers the feedback blueprint in web/web_setup.py (python -m scripts.enable_feedback)
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
Extension popup "See more in app" ──safebrowse://history──▶ DesktopApp/electron/main.cjs (protocol link) ──▶ pages/Home.tsx ──▶ pages/user/ScanApp.tsx (initialTab)
DesktopApp (Electron) ──/api/auth, /api/staff, /api/extension/pairing-code──▶ Backend/web/controllers/api_auth.py ──▶ web/db_models ──▶ Postgres
DesktopApp pages/user/scan ──scan requests / history──▶ Backend/web/controllers/scans.py ──▶ web/db_models/scans.py ──▶ Postgres
DesktopApp pages/user/feedback + pages/StaffFeedback ──/api/feedback, /api/staff/feedback──▶ Backend/web/controllers/feedback.py ──▶ web/db_models/feedback.py ──▶ Postgres (public.feedback)
Extension popup ──/api/extension/pair (code from the desktop app)──▶ Backend  ──▶ token kept in chrome.storage.local

aidev.detection.detector  reads  AIDev/lists/*.txt, AIDev/data/tranco_top.txt, feeds_urls.txt, adult_domains.txt
                          uses   predict.py (core/features.py + models/model.joblib), predict_content.py (models/model_content.joblib),
                                 lookalike.py, phishtank.py, safebrowsing.py, rdap.py
AIDev/aidev/pipeline: feeds, import_* ─▶ data/* ─▶ build_dataset ─▶ data/dataset.csv ─▶ train ─▶ models/model.joblib
                      crawl_pages / import_phreshphish ─▶ data/pages/ ─▶ train_content ─▶ models/model_content.joblib
```

Dependency direction: `aidev.core` <- `aidev.detection` <- (`aidev.pipeline`, `aidev.evaluation`, `aidev.tools`) <- `Backend/app.py`.
`aidev` never imports Backend. Backend imports only `aidev.detection.detector` (in `app.py`). Imports are absolute: `from aidev.core.common import DATA`, `from web.guards import auth_required`, `import config`.
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
- Secrets only in `.env` files; never commit them, `AIDev/data/`, `*.joblib`, or `benign_extra.csv` (your browsing history).
- `Backend/web/db_models/` are database tables; ML models are `AIDev/models/*.joblib`.
- `API_BASE` is duplicated in `Extension/chrome/background.js` and `Extension/ui/src/config.ts`; keep them equal.
- `tools/` and `scripts/` are manual helpers; nothing in production imports them.

## 6. Where to change what

| Task | Look in |
|---|---|
| Change how a verdict is decided / add a signal | `AIDev/aidev/detection/detector.py` (+ new module in `detection/`) |
| Add or change a URL feature | `AIDev/aidev/core/features.py`, bump `FEATURE_VERSION`, run `aidev.pipeline.train` |
| Page-content feature | `AIDev/aidev/detection/content_features.py`, then `aidev.pipeline.train_content` |
| Trust or block a domain by hand | `AIDev/lists/whitelist.txt`, `blacklist.txt`, `not_trusted.txt`, `protected_domains.txt` |
| New training data source | new `AIDev/aidev/pipeline/import_*.py` writing to `AIDev/data/`, read by `build_dataset.py` |
| Account / login / pairing API | `Backend/web/controllers/api_auth.py`, `Backend/web/db_models/*`, `Backend/web/security.py` |
| Settings | `Backend/config.py` + `Backend/.env.example` (account side), `AIDev/.env.example` (detector side) |
| Extension behaviour | `Extension/chrome/background.js` and the matching page; popup UI in `Extension/ui/src` |
| URL scanner screens (scan, result, detailed analysis, history) | `DesktopApp/src/pages/user/` (`ScanApp.tsx`, `scan/*`), `DesktopApp/src/lib/analysis.ts`, `DesktopApp/src/components/StatusBadge.tsx` |
| Scan / history API and storage | `Backend/web/controllers/scans.py`, `Backend/web/db_models/scans.py` |
| Feedback (submit, attach scan, edit, reply, status, close, search) | `Backend/web/controllers/feedback.py`, `Backend/web/db_models/feedback.py`; screens `DesktopApp/src/pages/user/feedback/Feedback.tsx`, `DesktopApp/src/pages/StaffFeedback.tsx`, shared `DesktopApp/src/components/feedback/`, `DesktopApp/src/lib/feedback.ts` |
| Desktop screens | `DesktopApp/src/pages`, API calls in `DesktopApp/src/api.ts`, Electron in `DesktopApp/electron/main.cjs` |
| ML numbers, data sources, known weaknesses | `AIDev/docs/ML_HANDOFF.md` |

## 7. Status (2026-10-29)

URL model: Random Forest, ROC-AUC about 0.87, recall about 67% at 0.5. Content model trained on page features; no trusted accuracy number yet (see `AIDev/docs/ML_HANDOFF.md`).
Extension pairs with the desktop app. Scan history is NOT kept in the browser: it is saved to the account and read in the desktop app (login required). Settings stay in `chrome.storage.local` behind `Extension/ui/src/store.ts` (Supabase later).
Open items: end-to-end re-test after the latest retrain, a hand-labelled test set, a time-based evaluation. The URL model file is ~720 MB (loaded at every Backend start).
