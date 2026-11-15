# HANDOFF: AI model 2 (page-content model), for a SEPARATE chat

Written Thursday 2026-11-12. The user's own deadline is **Sunday 2026-11-15** (3 days). Everything is cut to fit.
Status: A = waiting for the user's numbers. B, C, D, E, F CODE DONE and tested in the sandbox (47 unit tests pass; end-to-end run on SYNTHETIC pages only, real numbers need the user's PC). Next: user runs the commands in section 'Run these on your PC', pastes output; then G/H (SHOULD) and the final report.

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

## Work list (3 days)
**MUST (Thursday to Friday)**
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

**SHOULD (Saturday, only if time)**
- G. Compare RF with sklearn `HistGradientBoostingClassifier` under the same evaluation.
- H. Error analysis: 30 false positives and 30 false negatives, grouped by cause.

**SKIP before Sunday, write as future work in the report**
Headless rendering (Playwright in Docker), screenshots and visual similarity (pHash against a few Malaysian bank login pages), DOM-tree models, Wikidata official-site check, re-crawling for cloaking. Reason: they need a browser, Docker, network and weeks of data.

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
- 2026-11-12 (chat 2): read this file + content_features.py, train_content.py, predict_content.py (zip-patch @ 0b24c41) + data_sample.zip (only 5 html.gz; pages.csv 50 rows).
  Step A: the sandbox has no full data (468 MB stays on the user's PC), so the three baseline commands + source-count one-liner must be run by the user. Waiting for the pasted output.
  Observations for the report / error analysis (step H):
  * `group` = registered domain of the FINAL url. Several `phish_feed` rows are on shared platforms (tinyurl.com, qrco.de, adobe.com, vk.com, mailchimp.com, webwave.dev): the saved HTML is often the platform's own page (interstitial, redirect to mailchimp.com/about, vk away.php), so labels are noisy and every page of one platform lands in one group.
  * Some benign rows redirect to a different final domain (onlamp.com -> oreilly.com, code42.com -> mimecast.com): group follows final_url.
  * train_content.py: final model is refit on ALL data; printed metrics belong to the train/test fit (say so in the report).
- 2026-11-12 (chat 2): **Step B done.** `AIDev/aidev/evaluation/eval_content_own.py`: own pr_auc, roc_auc, recall_at_fpr (1%, 0.5%; marks `reliable:false` when fewer than 5 false positives are allowed), brier, ece, fpr_by_source, cluster bootstrap 95% CI (1000 resamples, about 1 s for 3,300 pages). CLI: `python -m aidev.evaluation.eval_content_own --pred preds.csv` (columns label,prob,group,source). Metrics cross-checked against scikit-learn in the tests only.
- 2026-11-12 (chat 2): **Step C done.** `AIDev/aidev/evaluation/campaign_dedup.py`: `html_fingerprint(html, final_url)` (normalised title + sorted foreign script/CSS hosts + form-action hosts + number of inputs; None for pages with no structure), `campaign_clusters(domains, fps, labels)` (connected components of domain--fingerprint via union-find; a fingerprint on more than 300 domains counts as generic and does not merge; reports clusters, merged domains, largest cluster share, mixed-label clusters), `cap_per_cluster(cluster, label, cap=20)` (cap per cluster and label, training rows only). Tests: `AIDev/tests/test_content_eval.py` (run from AIDev/: `python -m unittest tests.test_content_eval -v`).
  Not yet wired into a training script (comes with the new train_content2 after D/E). The real numbers (how many clusters, how many pages collapsed) need the full pages.csv on the user's PC.
- 2026-11-12 (chat 2): **Step D done.** `AIDev/aidev/detection/content_features.py` rewritten from the zip-patch@0b24c41 text with the six features appended at the END of FEATURE_NAMES; `CONTENT_FEATURE_VERSION = 3`. Existing features/names untouched (a `git diff` should show additions only, plus the two small changes below). Tests: `AIDev/tests/test_content_features_v3.py`.
  Design decisions (differences from the handoff text, please keep in the report):
  * `brand_asset_hotlink` counts images, style sheets and favicons, NOT scripts: legitimate sites load reCAPTCHA / Facebook / PayPal SDK scripts from brand domains and would be flagged.
  * `brand_in_logo_alt`: a brand name in a file name only counts when the file name contains "logo" (otherwise `apple-touch-icon.png` is on every benign site).
  * `form_posts_to_ip_or_http`: only ABSOLUTE actions count (http:// or an IP host). A relative action on an http page would just repeat the URL scheme, which this model deliberately excludes (collection bias).
  * Two small code changes outside the six features: (1) `<img>` handler now also records `alt`, `<meta>` handler also records og:site_name/application-name/description (n_images and meta_refresh behave exactly as before); (2) `foreign()` now returns None for a malformed URL such as `href="http://[bad"` instead of raising (before, one bad link made the whole page unscorable: skipped in training, "no opinion" online).
  * `redirect_cross_domain` still calls urlsplit on redirect URLs without a guard (left alone).
  * The old model_content.joblib is refused until train_content (or the new train_content2) is re-run (version 2 -> 3).
- 2026-11-12 (chat 2): **Steps E and F done (code).**
  * `AIDev/aidev/pipeline_own2/train_content2.py` (new; the old `train_content.py` is untouched so the baseline stays reproducible). Split by campaign into train/validation/test, cap 20 per campaign in training, RF (same hyper-parameters as before), isotonic calibration on validation, threshold = FPR <= 1% on benign validation, test report with CI, `--ablate` (groups: forms, brand_title, links_resources, scripts, size_text; redirects_tls only when not dropped), `--no-dedup` (old-style split, to show how much it flattered), `--only-v2`, `--no-size`, `--test-on own`, `--promote` (explicit copy to the live model).
  * Saved joblib = old keys + `calibrator`, `threshold`. Saved model is fitted on train+test (not validation); metrics printed are from the train-only fit.
  * `predict_content.py`: result keeps every old key; adds `probability_calibrated`, `threshold`, `flagged` (None when the model has no calibrator). `probability` is still the RAW forest output, so detector.py's existing cut-offs keep their meaning. Threshold read from Supabase setting `content_threshold` (list_store.setting) if present, else from the model file. NOTHING was written to Supabase. If the user wants the live threshold there: one row in `detection_settings` (key `content_threshold`, value = the threshold printed in the report), to be inserted by the user from a SQL snippet we write when the model is accepted.
  * Sandbox run on synthetic pages worked end to end (all modes). It also showed that chains of weak fingerprint matches can build one big cluster (200 of 2,500 pages): the report prints `largest_cluster_share` and a warning above 5%; check this number on the real data first.
  * Also added `AIDev/docs/content_model_code_statement.md` (own code vs libraries).

## Run these on your PC (from AIDev/, venv active; branch model2-improve)
```
python -m unittest discover -s tests -t . -v
python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid --out base_random      (step A)
python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid --no-size --out base_nosize
python -m aidev.pipeline.train_content --drop n_redirects,redirect_cross_domain,tls_invalid --test-on own --out base_own
python -c "import pandas as pd; p=pd.read_csv('data/pages/pages.csv'); print(p.groupby(['source','label']).size()); print(p.fetched_at.min(), p.fetched_at.max())"
python -m aidev.pipeline_own2.train_content2 --drop n_redirects,redirect_cross_domain,tls_invalid --out m2_v3 --ablate
python -m aidev.pipeline_own2.train_content2 --drop n_redirects,redirect_cross_domain,tls_invalid --only-v2 --out m2_v2
python -m aidev.pipeline_own2.train_content2 --drop n_redirects,redirect_cross_domain,tls_invalid --no-dedup --out m2_v3_nodedup
python -m aidev.pipeline_own2.train_content2 --drop n_redirects,redirect_cross_domain,tls_invalid --test-on own --out m2_v3_own
```
Paste back: the `campaigns:` line, the `split` line, and the "TEST" blocks + ablation lines of m2_v3; for the others only the `recall@fpr1%` and `fixed_*` lines. Do NOT run with --promote yet.
- 2026-11-14 (chat 2): user ran the commands from the wrong folder first (must be `D:\Desktop\FYP\AIDev`) and the zip was not yet unpacked into the repo (`tests/` missing). Fixed by instructions, no code change. Old `train_content.py` takes several minutes (it re-reads ~16,000 pages; no output until extraction ends).
  **Patch 2:** `train_content2.py` now caches the extracted features + fingerprints in `data/pages/features_cache.joblib` (git-ignored). Used only when pages.csv, content_features.py and campaign_dedup.py are byte-identical to the cached run (key = sha1 of pages.csv size/mtime + both source files + feature version), otherwise rebuilt automatically. `--no-cache`, `--rebuild-cache` override. Progress line every 2,000 pages. Model, split, metrics unchanged (verified: cached and fresh synthetic runs give identical results). New test `CacheTests`; 48 tests pass. Only `train_content2.py` and `tests/test_train_content2.py` changed.
- 2026-11-14 (chat 2): **Step A results (user's PC).** NOTE: the old `train_content.py` already used the six v3 features (it reads FEATURE_NAMES), so these are "v3 features + old random-domain split", NOT a v2 baseline. A true v2 baseline needs `--drop n_redirects,redirect_cross_domain,tls_invalid,brand_asset_hotlink,brand_in_logo_alt,brand_in_meta,n_ext_domains,login_form_no_own_links,form_posts_to_ip_or_http --out base_v2` (not run yet).
  pages 15,880 (phishing 7,016, benign 8,864), domains 13,898, 53 features used.
  | run | AUC | acc | prec | recall@0.5 | FPR@0.5 |
  |---|---|---|---|---|---|
  | base_random (random domain split) | 0.9460 | 0.881 | 0.897 | 83.3% | 7.9% |
  | base_nosize (10 size features dropped) | 0.9363 | 0.863 | 0.867 | 82.4% | 10.5% |
  | base_own (test only on own-crawled pages) | 0.7817 | 0.789 | 0.606 | 57.7% | 13.5% |
  base_random at 0.8: recall 60.2%, FPR 0.9%. Test benign is 1,170 of 1,405 PhreshPhish (83%), so the random split mostly measures phreshphish_benign vs the rest. Highest FPR source: benign_tail_login (20.9% at 0.5; 30.9% in base_own). benign_history has 3-5 test pages only (too few to read).
  base_own at 0.8: recall 25.4%, FPR 2.7%; at 0.9 recall 8.1%. => on the pages the live detector actually sees, the model is much weaker than the random split suggests (headline for the report: cross-source gap, AUC 0.946 -> 0.782).
  Top feature in all three runs: `n_ext_domains` (0.106 / 0.178 without size features / 0.112). It is NOT in SIZE_FEATURES, so --no-size does not remove it, and it grows with page size. To check in the ablation (links_resources group) and with a run that also drops it; suspected size / source proxy.
  The pandas source-count one-liner output: not received yet.
- 2026-11-14 13:33 (chat 2): **Step A results (user's PC).** NOTE: the old train_content.py already used the six v3 features (53 features after the 3 drops), so these are NOT the v2 baseline. True v2 baseline = rerun with the six v3 names added to --drop (command `base_v2` below, not run yet).
  | run | split | test pages | AUC | recall@0.5 | FPR@0.5 | recall@0.8 | FPR@0.8 |
  |---|---|---|---|---|---|---|---|
  | base_random (53 feats) | random by domain | ~3,200 (benign 1,751 of which 1,170 phreshphish_benign) | 0.946 | 83.3% | 7.9% | 60.2% | 0.9% |
  | base_nosize (43 feats) | random by domain | same | 0.936 | 82.4% | 10.5% | 59.9% | 1.1% |
  | base_own (53 feats) | own-crawled pages only, 30% of own domains | 1,161 (phishing 307, benign 854) | 0.782 | 57.7% | 13.5% | 25.4% | 2.7% |
  Data: pages 15,880 (phishing 7,016, benign 8,864), 13,898 domains. Benign sources in test: benign_history, benign_tail, benign_tail_login, benign_top, benign_top_login, phreshphish_benign.
  Findings: (1) the realistic own-pages test is far worse than the random split (AUC 0.78 vs 0.95; at threshold 0.9 recall only 8.1%): the random score is flattered by the PhreshPhish part / kit duplicates. (2) `n_ext_domains` is the top feature in every run (0.106 / 0.178 without size features / 0.112): must be checked by ablation and by dropping it (command `m2_v3_no_extdom`). (3) Highest false-positive rates are on `benign_tail_login` (20.9% at 0.5, 30.9% on own pages) = small sites' login pages.
  The source-count one-liner (pages.csv groupby source,label) was started but not finished: re-run (instant).
  Still to run: m2_v3 --ablate, m2_v2, m2_v3_nodedup, m2_v3_own, base_v2, m2_v3_no_extdom.
- 2026-11-14 15:40 (chat 2): **All user runs finished** (m2_v3 --ablate, m2_v3_own, m2_v3_no_extdom, m2_v2, m2_v3_nodedup, base_v2). Numbers are written up in `AIDev/docs/content_model_results.md`. Main findings:
  * campaigns: 15,880 pages -> 11,737 clusters, 487 multi-domain, largest 1.3%, 87 mixed-label; cap removed 544 training pages.
  * campaign split (m2_v3): PR-AUC 0.938 [0.915,0.957], ROC 0.944, recall@1%FPR 0.538 [0.459,0.641]. Old-style no-dedup: 0.947 / 0.951 / 0.617 [0.563,0.669] (optimistic direction, intervals overlap). Own pages only: PR-AUC 0.610, ROC 0.794, recall@1%FPR 0.131 [0.081,0.250].
  * v3 features: NO measurable gain (v2 PR-AUC 0.937, v3 0.938; old split AUC 0.945 vs 0.946). n_ext_domains is top by importance but removing it changes nothing.
  * ablation: biggest drops brand_title and links_resources (-0.013 PR-AUC), within CI width.
  * calibration: ECE 0.048 -> 0.019 on the mixed test, but worse on own pages (0.085 -> 0.104); the threshold chosen on mixed validation gives FPR 0.0% on the mixed test and 2.0% on own pages (target 1%), recall 0.399 / 0.266.
  * phish_feed (own crawl) recall at the 1% point only 0.200 vs phreshphish_phish 0.595.
  **Patch 3** (this zip): `train_content2 --model hgb` (step G); `evaluation/error_analysis.py` (step H: cause rules, 30 random FP/FN, URLs defanged, history URLs hidden); `evaluation/feature_coverage.py` (how often each feature fires per class/source, to explain the v3 null result); tests (55 pass); `docs/content_model_results.md` (draft results text).
  Still to run: hgb comparison, feature_coverage, error_analysis on m2_v3 and m2_v3_own, source-count one-liner. Then: final zip, code statement already in docs/. Possible follow-up if time: choose the threshold on own-crawled validation pages only.
- 2026-11-14 22:00 (chat 2): user said the Sunday date is only a self-set limit; there is time to improve the real results. User also wants the result to "reach accuracy": told them no number can be promised, results are reported as they are; the old 0.88 accuracy was at probability 0.5 with 7.9% false positives, not comparable with the 1%-FPR operating point.
  **Patch 4** (tests: 58 pass): `train_content2` gets `--own-weight W` (pages crawled by ourselves weigh W, PhreshPhish pages 1) and `--val-own-only` (isotonic calibration and threshold from own-crawled validation pages, which look like the live ones); the raw report now includes accuracy / recall / FPR / precision at probability 0.5 (comparable with the old reports); new `evaluation/summarize_runs.py` (one table from several experiments; `--mean` for seeds).
  Reason: training data is about 3/4 PhreshPhish, the model learns that style; own-crawled test AUC is only 0.79.
  Experiment plan (avoid tuning on the test set): pick the setting on seed 42, then CONFIRM the winner on seeds 7 and 11 and report the mean +- spread.
  1. `--test-on own` with --own-weight 1 / 3 / 6, with and without --val-own-only, RF and hgb.
  2. Winner: rerun with --seed 7 and --seed 11, `summarize_runs "NAME_s*" --mean`.
  3. Error analysis on the winner; then decide whether feature work is worth it (depends on the causes: shared-platform pages and tiny pages cannot be fixed by features).
- 2026-11-14 23:30 (chat 2): user ran patch-3 tools (patch 4 not yet unpacked: 55 tests ran, own-weight options not yet available to them). Results:
  * source counts: benign_history 14, benign_tail 1,709, benign_tail_login 221, benign_top 925, benign_top_login 131, phish_feed 1,021 (the only own-crawl phishing), phreshphish_benign 6,000, phreshphish_phish 6,000. Fetch dates 2024-07-02 .. 2026-10-19.
  * feature_coverage: brand_asset_hotlink fires 6.7% phishing vs 12.3% benign (wrong direction), brand_in_logo_alt 10.7% vs 19.4% (wrong), brand_in_meta 5.8% vs 2.1% (right, rare), login_form_no_own_links 11.2% vs 2.3% (right, rare), form_posts_to_ip_or_http 0.2% vs 0.2% (never fires), n_ext_domains>0 79% vs 95%. => the brand-hotlink hypothesis is NOT supported by this data; explains the v2-vs-v3 null result. Written into docs/content_model_results.md (sections 7-9).
  * hgb vs RF: campaign split PR-AUC 0.940 vs 0.938, recall@1%FPR 0.582 vs 0.538 (CIs overlap), raw ECE 0.018 vs 0.048, validation threshold transfers well on the mixed test (recall 0.573, FPR 0.9%); own pages PR-AUC 0.598 vs 0.610, same weakness (fixed recall 0.240, FPR 2.1%).
  * BUG found by the user's run: `error_analysis.py` crashed (`'int' object has no attribute 'lower'`) because the preds CSV stores numeric campaign ids in `group`; fixed (domain now taken from the feature table); test now mirrors the real file. 
  * Delivered ONE cumulative zip `model2_all.zip` (supersedes patches 1-4): unpack once over the repo.
  Next: user unpacks, reruns error_analysis (both preds files), then the own-weight / val-own-only runs (see message), then seeds 7 and 11 for the winner.
- 2026-11-14 23:45 (chat 2): user unpacked model2_all.zip (58 tests OK) and ran error_analysis + own-weight runs.
  * error_analysis own (m2_v3_own): 232/267 phishing missed at 1% FPR; causes: tiny page 41.8%, no form 23.7%, form but nothing sensitive 22.8%, redirector 9.1%, credential form 2.6%. FPs (8): 62.5% tiny pages. Mixed test: 614/1,330 missed (462 phreshphish, 152 phish_feed); 17 FPs, 76.5% tiny pages. Missed own-crawl URLs are mostly link shorteners / redirect pages / legitimate form platforms (saved HTML = the platform's page; label belongs to the URL). The `shared_hosts.txt` rule caught almost none (0.7%): shorteners are not in that list.
  * own-weight (own pages, seed 42): w1 ROC 0.794 / PR 0.610; w3 0.808 / 0.626; w6 0.811 / 0.622: gain far inside CI. Accuracy@0.5 0.81-0.82 on own pages (recall 0.56, FPR 0.10-0.115). val-own-only: same model as w3; threshold 0.875 gives recall 0.109, FPR 0.5%.
  * OPEN QUESTION (diagnostic added to error_analysis.py, section "Are the catches coming from page length alone?"): tiny pages get high scores both for phishing and benign pages; if most caught phishing pages are tiny pages, the model's own-page skill is largely "short page = suspicious". User to rerun error_analysis (m2_v3_own, own_w3, m2_v3). Depending on the answer: option A, abstain on tiny pages (probability None = no opinion, same convention as JS-only pages; report coverage honestly); option B, keep as is and state the limitation.
  * results doc extended (sections 11-12; limits now section 13).
- 2026-11-15 06:20 (chat 2): user ran patch-4 options + error analysis. Results (all in docs/content_model_results.md sections 10-12):
  * error analysis own pages: 232/267 phishing missed at the 1%-FPR point; causes: tiny page 41.8%, no form 23.7%, form nothing sensitive 22.8%, redirector 9.1%, credential form 2.6%. About 20 of 30 sampled misses are on shorteners / QR redirectors / survey+form builders / free hosts (saved page = platform's own). Benign FPs mostly tiny pages (62%-76%).
  * own-weight 1/3/6: PR-AUC 0.610/0.626/0.622, ROC 0.794/0.808/0.811, recall@1%FPR 0.131/0.142/0.150: not significant (CI width ~0.07). Default stays weight 1. accuracy@0.5 own pages 0.81 (recall 0.56-0.57, FPR 10-11.5%, precision 0.61-0.64). val-own-only changes only the calibrated threshold (recall 0.109 at FPR 0.5%).
  * NOTE: while I worked, `AIDev/aidev/evaluation/error_analysis.py` on disk gained a `readability()` function and a "Are the catches coming from page length alone?" table that I did not write (not in the user's earlier run output). Kept it; made it tolerant of missing columns.
  * New in this round: `evaluation/platform_domains.py` (domain with >= 5 phishing pages = platform / shortener; domain+label only, never a prediction; defined AFTER the first error analysis, so exploratory), used by error_analysis (cause "shared hosting / link-shortener platform") and by train_content2 (supplementary block `without_platform_phishing` in the report: same test pages without phishing pages on such domains; printed as "exploratory"). 60 tests pass in the sandbox.
  Still open: seeds 7 and 11 for w1 and w3 (only if the user wants a claim about weighting); rerun m2_v3 / m2_v3_own to get the exploratory block; final zip = model2_all.zip (cumulative).

## 2026-11-16 (model 2 chat)
- m2_v3_final and m2_v3_own_final re-run on the user's PC: every number identical to m2_v3 / m2_v3_own (reproducible, seed 42).
- Accuracy at probability 0.5 added to docs/content_model_results.md section 2 (campaign split 0.877; own pages 0.810).
- Docs sections renumbered 1-12 (old file jumped from 9 to 11).
- OPEN: the exploratory platform-domain block prints "without 0 phishing test pages" on both real runs. The logic works on a toy
  example, so the cause is in the real `group` values. Diagnostic for the user:
  python -c "import joblib,pandas as pd; d=joblib.load('data/pages/features_cache.joblib')['df']; p=d[d.label==1]; print(p.group.value_counts().head(12)); print(d[d.url.str.contains('qrco.de')][['url','group','source']].head())"
  No exploratory number may be claimed until this is resolved.
- The zip sent earlier on 2026-11-15/16 had the old doc and handoff; superseded by the zip below.

## 2026-11-16 00:55 (model 2 chat)
- DIAGNOSED: platform rule excluded 0 pages because cache `group` = landing domain (qrco.de/bftmjd has group linkedin.com);
  max 4 phishing pages per group. Fix: `platform_domains.url_domain(url)` = registered domain of the submitted URL; used in
  train_content2.evaluate_split and error_analysis.analyse. Tests updated (group now landing domain, as in real data).
- TODO (user): re-run `m2_v3_final` / `m2_v3_own_final` (same names ok, numbers outside the exploratory line must stay identical)
  and `error_analysis` for both; then read the exploratory line. Do not quote it before.

## 2026-11-16 01:00 (model 2 chat)
- User PC: 60 tests OK. m2_v3_final2 reproduces all main numbers; exploratory platform rule now works.
  campaign split: 57/1330 phishing removed -> PR-AUC 0.946, ROC 0.954, recall@1% 0.561, acc@0.5 0.888.
  own pages: 65/267 removed -> PR-AUC 0.633, ROC 0.856, recall@1% 0.173, acc@0.5 0.843. Documented in results section 12.
- Next (optional): error_analysis re-run for both preds files (now uses submitted host); seeds 7/11; threshold on own validation.

## 2026-11-16 01:10 (model 2 chat): end-to-end check on synthetic data
- Ran in the sandbox on synthetic pages (plumbing only; synthetic data is trivially separable, so metrics of 1.0 mean nothing):
  train_content2 default / --test-on own / --model hgb / --own-weight 3 --val-own-only / --ablate --no-cache / --promote,
  then error_analysis, summarize_runs, feature_coverage, eval_content_own CLI: all ran without errors.
- Promoted bundle loads: keys calibrator, feature_names, feature_version (== content_features), model, threshold; one HTML
  page goes through extract -> model -> calibrator -> threshold -> flagged. Zip unpacks with the repo's relative paths and compiles.
- Known cosmetic: sklearn warns "X does not have valid feature names" (predict_content passes a list, as in the old code).
- Edge case: on perfectly separable data the saved threshold can be ~0 (5e-324); not reachable on real data (0.87 / 0.80).
- Not testable in the sandbox: pagefetch / page_signals (model 1 files, no network). The user's PC ran those tests: 60 OK.
