# Phase 0 — Repository & Model Discovery Report (`IMPLEMENTATION_DISCOVERY.md`)

**Branch:** `integrate/upgrade-model`  
**Date:** 2026-11-19  
**Status:** Discovery complete; awaiting user approval on architecture and security decisions before modifying application code.

---

## 1. Existing Application Map

| Layer | Entry Points & Key Files | Notes |
|---|---|---|
| **Backend API** | [Backend/app.py](Backend/app.py), [Backend/web/web_setup.py](Backend/web/web_setup.py), [Backend/web/controllers/scans.py](Backend/web/controllers/scans.py) | Python + Flask (`POST /analyze`, `POST /api/scans`, `GET /api/scans`, `GET /api/scans/<id>`). Currently synchronous. |
| **Static Scanner** | [AIDev/aidev/detection/detector.py](AIDev/aidev/detection/detector.py), [AIDev/aidev/detection/pagefetch.py](AIDev/aidev/detection/pagefetch.py) | `detector.analyze(url, use_ai=...)` checks local/Supabase lists, PhishTank, look-alike rules, Google Safe Browsing, RDAP domain age, AI 1, and AI 2 (`pagefetch.fetch` + `predict_content`). |
| **Frontend (DesktopApp)** | [DesktopApp/src/pages/user/scan/UrlScanner.tsx](DesktopApp/src/pages/user/scan/UrlScanner.tsx), [ScanResult.tsx](DesktopApp/src/pages/user/scan/ScanResult.tsx), [DetailedAnalysis.tsx](DesktopApp/src/pages/user/scan/DetailedAnalysis.tsx), [DesktopApp/src/lib/analysis.ts](DesktopApp/src/lib/analysis.ts) | Electron + React + TypeScript + Vite. Submits `POST /api/scans` and renders `analysis` JSON (`checks`, `ai1`, `ai2`, `ai_combined`, `final`). |
| **Browser Extension** | [Extension/chrome/background.js](Extension/chrome/background.js), [Extension/ui/src/](Extension/ui/src/) | Chrome MV3 extension calling `/analyze` or `/api/scans`. |
| **Database (Supabase)** | [Backend/web/db_models/scans.py](Backend/web/db_models/scans.py) | Postgres (`detection_history` stores `analysis jsonb` capped at ~20 KB in `scans.py`; `global_urls` stores shared threat entries). |
| **Queue / Workers** | None | No Celery/RQ/Redis queue exists; all scans run inline in Flask request threads. |
| **Docker Setup** | None in repo | No `Dockerfile` or `docker-compose.yml` exists. Host has `Docker version 29.9.3` installed, but the **Docker daemon is not currently running** (`//./pipe/docker_engine` unavailable). |
| **Tests & Build** | `AIDev/tests/` (79 `unittest` cases), `DesktopApp` (`npm run build`, `npx tsc --noEmit`), `Backend` (`py_compile`) | All 79 `AIDev` unit tests pass. |

---

## 2. Verified Model Contracts

### AI 1 — URL Lexical Model (`AIDev/models/model.joblib`)
- **Loader:** [AIDev/aidev/detection/predict.py](AIDev/aidev/detection/predict.py)
- **Feature Extractor:** [AIDev/aidev/core/features.py](AIDev/aidev/core/features.py) (`FEATURE_VERSION = 3`)
- **Inputs (29 fixed float features in exact order):**  
  `host_length`, `path_length`, `num_dots_host`, `num_hyphens_host`, `num_digits_host`, `digit_ratio_host`, `num_subdomains`, `host_is_ip`, `has_at_symbol`, `num_path_segments`, `num_suspicious_words`, `risky_tld`, `host_entropy`, `has_punycode`, `longest_host_label`, `path_special_chars`, `reg_label_length`, `tld_length`, `num_host_tokens`, `avg_token_length`, `max_consonant_run`, `vowel_ratio_host`, `digit_letter_switches`, `brand_mismatch`, `path_has_risky_ext`, `path_pct_encoded`, `path_digit_ratio`, `longest_path_token`, `path_double_slash`.
- **Output:** `probability` (0..1), `risk_score` (0..100), `top_features`.
- **Known Limitation:** Static URL string only; `model.joblib` currently on disk is a 30-feature `HistGradientBoostingClassifier` while `predict.py` on this branch expects 29 features (fails open with `None`).

### AI 2 — Page-Content Model (`AIDev/models/model_content.joblib`)
- **Loader:** [AIDev/aidev/detection/predict_content.py](AIDev/aidev/detection/predict_content.py)
- **Feature Extractor:** [AIDev/aidev/detection/content_features.py](AIDev/aidev/detection/content_features.py) (`CONTENT_FEATURE_VERSION = 3`)
- **On-disk Artifact:** `RandomForestClassifier` (`version: content-20261115-1648`, `feature_version: 3`, `IsotonicRegression` calibrator, `threshold: 0.8235`).
- **Inputs:** `(html: str, final_url: str, redirects: list[str], tls_invalid: bool)` → fixed vector of **38 features** (`n_forms`, `has_password`, `has_sensitive_input`, `form_posts_external`, `form_posts_ip`, `n_iframes`, `has_hidden_iframe`, `has_meta_refresh`, `has_eval_obfuscation`, `title_domain_mismatch`, `n_links`, `ext_link_ratio`, `n_tags`, `n_images`, `log_text_len`, `log_html_len`, `n_words`, `text_per_tag`, `n_scripts`, `ext_script_ratio`, `log_inline_script_len`, `title_len`, `has_favicon`, `ext_favicon`, `has_copyright`, `n_redirects`, `redirect_cross_domain`, `tls_invalid`, `has_lang_attr`, `brand_asset_hotlink`, `brand_in_logo_alt`, `brand_in_meta`, `n_ext_domains`, `login_form_no_own_links`, `form_posts_to_ip_or_http`, etc. — exact list in `content_features.FEATURE_NAMES`).
- **Output:** `probability`, `probability_calibrated`, `threshold`, `flagged`, `signals`, `download`, `page_signals`.
- **Limitation:** Reads static HTML from `requests.get()` in `pagefetch.py` (no JavaScript execution; SPA/JS-rendered pages look empty). Cannot directly accept new dynamic fields (console errors, runtime XHR/fetch requests, popups) without bumping `CONTENT_FEATURE_VERSION` and retraining.

---

## 3. Discovery Decisions & Proposed Integration

1. **Preserve Static Scan & Model Contracts:** Keep `POST /api/scans` and `detector.analyze()` unchanged for fast static verdicts. Do **not** alter `FEATURE_NAMES` or retrain `model.joblib` / `model_content.joblib`.
2. **Dynamic Evidence as a Separate Assessment First:** Because AI 2's contract is fixed to 38 static-HTML features, dynamic browser observations (redirects, network requests, loaded scripts, frames, popups, download attempts, console/page errors, post-load DOM indicators) will be stored and displayed as a **separate `dynamic` assessment section** alongside the static result.
3. **Async Background Job Lifecycle:** Running Chromium in Docker takes ~5–20 seconds. Rather than blocking `POST /api/scans`, add an opt-in dynamic scan endpoint (e.g., `POST /api/scans/<id>/dynamic` + `GET /api/scans/<id>/dynamic`) backed by a bounded worker pool and a `dynamic_scans` table (or columns on `detection_history`) with states: `queued`, `running`, `completed`, `partial`, `failed`, `timed_out`.

### Proposed Files to Add / Modify (by Milestone)
- **Milestone B & C (Isolated Docker + Playwright Worker):**
  - `Scanner/Dockerfile` — minimal Python + Playwright + Chromium image, non-root user.
  - `Scanner/worker.py` — bounded Playwright runner outputting strict schema v1 JSON to stdout.
  - `Scanner/egress_proxy/` (if using proxy-based SSRF isolation) — public-web allow / private-IP deny egress filter.
  - `Scanner/docker-compose.yml` — hardened container settings (`cap_drop: ALL`, `no-new-privileges`, `read_only`, `tmpfs`, CPU/RAM/PID limits).
- **Milestone D & E (Backend Orchestrator + Persistence + Validation):**
  - `Backend/web/services/dynamic_scanner.py` — URL/DNS SSRF pre-check, disposable container orchestration (`docker run --rm`), strict timeout/cleanup, JSON schema validation & size caps.
  - `Backend/web/db_models/dynamic_scans.py` + migration script — persist job status & bounded dynamic evidence.
  - `Backend/web/controllers/scans.py` — `POST /api/scans/<id>/dynamic` and `GET /api/scans/<id>/dynamic` with rate & concurrency limits.
- **Milestone F (Frontend Reporting):**
  - `DesktopApp/src/pages/user/scan/DetailedAnalysis.tsx` & `ScanResult.tsx` — "Run Deep Dynamic Scan" action + separate Dynamic Observations card (facts, indicators, limitations).
- **Milestone G (Tests & Docs):**
  - `Backend/tests/test_dynamic_scanner.py` (functional fixtures + SSRF/timeout/cleanup tests) and `Scanner/README.md`.

---

## 4. Environment & Security Items Requiring Confirmation

1. **Docker Daemon Not Running:** Docker 29.9.3 is installed, but the daemon is currently stopped. Docker Desktop (Linux containers / WSL2) must be started to build and test Milestone B+.
2. **SSRF / Egress Isolation Approach:** Docker's default bridge network allows reaching host/LAN/private IPs. Should we implement an **isolated internal Docker network + dedicated egress proxy container** (blocking RFC1918/loopback/link-local/metadata IPs at the network layer in addition to Playwright request interception), or keep dynamic scanning **local/dev-only** until a Linux/cloud egress firewall is configured?
3. **Database Schema Addition:** Approval to add a `dynamic_scans` table in Supabase (preserving all existing tables and scan records) when we reach Milestone D.
4. **Desktop UI Trigger:** Should dynamic scanning be **on-demand** (a "Run Deep Dynamic Scan" button on Scan Result / Detailed Analysis) so real-time extension browsing stays fast, or triggered automatically on manual scans?
