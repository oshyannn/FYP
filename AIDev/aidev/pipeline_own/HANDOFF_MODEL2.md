# HANDOFF: AI model 2 (page-content model), for a SEPARATE chat

Written 2026-11-12, updated 2026-11-14. **Time: the user's Sunday 2026-11-15 date is self-set and NOT a real deadline (confirmed 2026-11-14). Do the work properly; quality of the detection comes first; no shortcuts.** Earlier text saying "3 days" or "1 day left" is obsolete.
Status: nothing done yet. Next: step A.

## First thing to do in this chat
1. Read this whole file.
2. Find out what you can access. If you have a GitHub tool, read the repo (below). If not, ask the user to upload these files from `AIDev/aidev/`: `detection/content_features.py`, `pipeline/train_content.py`, `detection/predict_content.py`, `detection/pagefetch.py`, `detection/page_signals.py`, `detection/page_threats.py`, `pipeline/crawl_pages.py`, `pipeline/import_phreshphish.py`, plus `data_sample.zip` (a 50-row sample of `AIDev/data`, includes `pages/pages.csv` and 5 sample `.html.gz`).
3. Tell the user in 3 lines what you understood, then start at step A.

## User and rules
- Student; final year project: real-time malicious URL detection (Flask, scikit-learn, Electron desktop app, Chrome extension, Supabase). Works in the VS Code terminal on Windows (`D:\Desktop\FYP`).
- Writes mixed Chinese/English. Reply in Chinese with English technical terms.
- **Other people's datasets are fine. The training and evaluation code must be the user's own: write it from scratch; only general libraries (pandas, numpy, scikit-learn). No copied phishing-detection projects, no pretrained phishing models.**
- Update this file after every step. When the usage limit is near, write down exactly what is done and where you stopped. When the work is finished, give a zip.
- Never ask for or touch `.env`, API keys, `benign_extra.csv` (private Chrome history).
- The sandbox has no internet. Anything that downloads or crawls is a script the user runs on their own PC.
- Safety: never open phishing URLs in a normal browser; never run page JavaScript; never enter credentials. Crawling only through the existing `pagefetch.py`.

## Repo and who edits what
Repo: github.com/oshyannn/FYP, branch `zip-patch`. Code in `AIDev/aidev/{core,detection,pipeline,evaluation,tools}/`. Run from `AIDev/` as `python -m aidev.<folder>.<module>`.
Another chat is improving **model 1** (URL model) at the same time. **Do not edit**: `core/features.py`, `pipeline/train.py`, `pipeline/build_dataset.py`, `detection/predict.py`, `detection/detector.py`, `pipeline_own/`.
**You own**: `detection/content_features.py`, `pipeline/train_content.py` (or new files under `pipeline_own2/`), `detection/predict_content.py`, `evaluation/`.
Tell the user to work on git branch `model2-improve`. Deliver changes as a zip of new/changed files with the same relative paths; the user merges. Do not push to GitHub unless the user asks.

## What model 2 is today (read from the code)
- Random Forest (300 trees, `class_weight="balanced_subsample"`, min_samples_leaf 2) on **50 static-HTML features** (`content_features.py`, `CONTENT_FEATURE_VERSION = 2`). Stdlib `HTMLParser`, no JavaScript is run.
- Feature groups: forms and password/sensitive inputs (`n_sensitive_inputs`, `form_external_action`, `form_null_action` ...), links and resources (`ext_link_ratio`, `ext_resource_ratio` ...), title and brand (`brand_in_title_not_domain`, `title_matches_domain` ...), scripts (`obfuscation_density`, `js_redirect`, `hidden_iframe` ...), page size and text (`n_links`, `n_tags`, `log_html_len`, ...), redirects and TLS (`n_redirects`, `redirect_cross_domain`, `tls_invalid`).
- Online path: `predict_content.predict(url)` -> `pagefetch.fetch` (static fetch) -> `extract` -> RF probability. It returns None (no opinion, never "safe") when the page is unreachable, not HTML, or JavaScript-only. Result keys are consumed by `detector.py` and `page_threats.assess()`: **do not rename or remove keys or existing feature names**; only add.
- Training: `train_content.py` re-extracts features from the saved HTML (`data/pages/html/*.html.gz`, listed in `data/pages/pages.csv`: `url,label,source,group,final_url,status,tls_invalid,redirects,html_file,fetched_at`). Options: `--drop`, `--no-size` (cheating check), `--time-split`, `--test-on own`, `--no-own-train`, `--out NAME` (ALWAYS use for experiments; saves under `AIDev/experiments/`). The user's current command: `--drop n_redirects,redirect_cross_domain,tls_invalid` (those three are collection artefacts).
- Data: `pages.csv` has about 16,021 rows and 15,880 html files (468 MB; stays on the user's PC). Sources seen in a 50-row sample: `benign_top`, `benign_top_login`, `benign_tail`, `benign_tail_login`, `phish_feed`; all fetched within seconds on 2026-10-19. About 13 of 50 sample rows were phishing. PhreshPhish rows (`source` starting `phreshphish_`, dates 2024-25) were NOT seen in the sample: check the full file (one-liner below).

## Weaknesses found (the reasons for the work list)
1. **Evaluation is thinner than it looks.** Default split is random by registered domain. `--time-split` sorts by `fetched_at`, which is crawl time, so it is a cross-source test, not a time test (the script says so itself). `--test-on own` is the closest to what runs online. No PR-AUC, no recall at a fixed false-positive rate, no calibration, no confidence interval. The saved model is refit on ALL data, so the printed metrics belong to a different fit than the saved file (normal, but say it in the report).
2. **Phishing-kit duplicates are not removed.** Group = registered domain only, so near-identical kit pages on different domains can sit in train and test and flatter the result.
3. **Static HTML only.** Content built by JavaScript is invisible; cloaking is not handled. This is a limit to state in the report, not to fix before Sunday.
4. **Missing brand-imitation signals** that static HTML can still show: a cloned page often hotlinks images/CSS from the real brand's domain, and names the brand in logo alt text or meta tags.
5. Collection bias risk: phishing pages that are still alive when crawled, and benign sources fetched differently. The `--no-size` run is the existing check; keep it in the report.

## Work list (full scope; order = value for the report and the least risk to the running app)
Why this order: A, B, E, F give honest numbers, a calibrated threshold and the ablation table without breaking the running app. C (campaign dedup) and D (new features, FEATURE_VERSION 3) need a retrain: do them after A and B, test each against the same split, and keep a change only if it helps. G and H (compare models, error analysis) follow.
Extra fact from the PhishTank feed (see HANDOFF.md): 42.6% of verified PhishTank URLs sit on shorteners, QR services and big legit sites. Expect many page crawls of those to land on the legitimate site; check `pages.csv` for phishing rows whose final page is a normal site before trusting recall.

**MUST**
- **A. Baseline.** Run the three commands below, save each with `--out`, paste the numbers to the user. Also run the source-count one-liner.
- **B. Own evaluation module** `evaluation/eval_content_own.py` (write it yourself): PR-AUC; recall at fixed FPR of 1% and 0.5% (0.1% is not measurable with a few thousand test pages, say so); false-positive rate per benign `source`; bootstrap 95% confidence interval resampling by group/cluster.
- **C. Campaign dedup.** Write `html_fingerprint(html)`: hash of normalised title + sorted external script/CSS hosts + form action host + number of inputs (own design). Build the split group as connected components of (domain, fingerprint), so no kit straddles train and test. Cap each cluster at 20 pages in training. Report how many clusters and how many pages were collapsed.
- **D. New features, version 3** (add only; bump `CONTENT_FEATURE_VERSION` to 3; each one gets a unit test on a tiny HTML string):
  1. `brand_asset_hotlink`: any image/script/CSS/favicon URL whose registered-domain label is in `BRANDS` and is not this page's domain.
  2. `brand_in_logo_alt`: brand name in an `<img alt>` or logo file name, brand not this domain.
  3. `brand_in_meta`: brand in `og:site_name`, `application-name` or meta description, brand not this domain.
  4. `n_ext_domains`: log1p of the number of distinct foreign registered domains among links and resources.
  5. `login_form_no_own_links`: has a password field and no same-domain link.
  6. `form_posts_to_ip_or_http`: form action host is an IP address or plain http.
- **E. Calibration + threshold.** Isotonic calibration fitted on a validation split made by cluster (not on test). Pick the threshold at FPR <= 1% on benign validation. Store it in the joblib as `threshold`; add `threshold` to the `predict()` result without changing existing keys.
- **F. Ablation by feature group** (forms, brand/title, links/resources, scripts/obfuscation, size/text, redirects/TLS): table of PR-AUC and recall at 1% FPR with each group removed. This is the best evidence for the report.

**SHOULD**
- G. Compare RF with sklearn `HistGradientBoostingClassifier` under the same evaluation.
- H. Error analysis: 30 false positives and 30 false negatives, grouped by cause.

**SKIP before Sunday, write as future work in the report**
Headless rendering (Playwright in Docker), screenshots and visual similarity (pHash against a few Malaysian bank login pages), DOM-tree models, Wikidata official-site check, re-crawling for cloaking. Reason: they need a browser, Docker, network and weeks of data.

## UI rule (user requirement)
Every result the user sees must show a score, a LIST of what was detected, and a short explanation. Every new content feature must also be able to appear as a plain-language line in that list (check how `predict_content.py` builds its signals today and follow it). A page that cannot be read must show "no opinion" and the reason, never a blank. Do not rename or remove result keys that `detector.py` and the UI read.

## Commands (from `AIDev/`, venv active)
```
python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid --out base_random
python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid --no-size --out base_nosize
python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid --test-on own --out base_own
python -c "import pandas as pd; p=pd.read_csv('data/pages/pages.csv'); print(p.groupby(['source','label']).size()); print(p.fetched_at.min(), p.fetched_at.max())"
```
After feature changes the old `model_content.joblib` is refused by `predict_content.py` until `train_content` is re-run.

## Supabase and lists (checked 2026-11-12 on the user's project "Detection System", ref flsdsogumbfnycknqauv)
- The live detector reads lists through `AIDev/aidev/core/list_store.py`. Small lists: table `detection_lists (list_type, value, note, is_active, created_at)`, fallback `AIDev/lists/<name>.txt`. Big lists: `trusted_top_sites` (20,000 rows), `threat_feed_urls` (28,325), `adult_domains` (998,930), cached in `AIDev/data/cache/`, freshness in `list_sync_status`. Numbers: `detection_settings` (key/value; today only `whitelist_top_n`), read with `list_store.setting(key, default)`.
- Allowed `detection_list_type` values: whitelist, blacklist, shared_hosts, protected_domains, not_trusted, trusted_prefixes, trusted_suffixes, adult_manual. Do NOT add a new type (needs ALTER TYPE plus edits in `list_store.SMALL_TYPES` and `sync_to_supabase.SMALL_FILES`); reuse an existing one.
- Upload command: `python -m aidev.pipeline.sync_to_supabase lists` (adds only) or `big` (replaces a whole table in one transaction).
- Rules for anything new:
  1. A list the LIVE detector reads (e.g. Malaysian banks / e-wallets / government domains as extra `protected_domains`) goes into Supabase as rows of an existing type, and the same entries are kept in `AIDev/lists/<name>.txt` as the fallback. Read it with `list_store.small(...)`.
  2. A runtime number (e.g. a model threshold) goes into a `detection_settings` row and is read with `list_store.setting("<key>", default)`. The model file also stores its own calibrated threshold as the fallback.
  3. Training data (the dataset table of 190k+ rows, page HTML) stays in local files under `AIDev/data/`, NOT in Supabase: too big, training must work offline, and the data is not in git.
  4. Other tables that exist: `ai_models` (1 row; update it with the new metrics when a model is accepted), `feedback` (6 rows), `detection_history` (266), `global_urls` (34 admin-approved threats), `threat_submissions` (7).
  5. Do not write to Supabase without telling the user exactly what will be inserted. Prefer a SQL or Python script the user can read and run.
- These detection modules ALREADY exist in `AIDev/aidev/detection/` and are combined by rules in `detector.py`: `cert_history.py`, `domain_age.py`, `rdap.py`, `official_site.py`, `popularity.py`, `lookalike.py`, `phishtank.py`, `safebrowsing.py`, `page_signals.py`, `page_threats.py`, `pagefetch.py`. Do not re-implement them. (`detector.py.before_optional_ai.bak` is an old backup; leave it out of any zip.)

## Deliverables
- This file, updated after each step.
- Final zip: changed/new code, `experiments/*.json`, a markdown results table (baseline vs new, per source, with confidence intervals, ablation), and a short "code source statement" (what is the user's own code, which libraries were used).

## Progress log
- 2026-11-12: handoff written. Nothing run yet.
- 2026-11-14: date confusion resolved: the Sunday date is self-set, not real; full work list restored.
