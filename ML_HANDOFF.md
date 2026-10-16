# ML Handoff: Random Forest URL Classifier

Project: Real-Time Malicious URL Detection System (BMCS3403). Last updated 2026-10-15.
Read with `FYP_MASTER_RECORD.md` (section 10) and `file_structure.md`.

Evidence rule: **[ran]** = numbers the student pasted from their own machine; **[tested]** = checked in the builder's sandbox on synthetic data or mocks only; **[judgement]** = reasoning, not verified.

## 1. Status at a glance

| Item | State |
|---|---|
| Model | Random Forest (scikit-learn, 300 trees) on lexical URL features. Matches the thesis wording |
| Trained on real data | **Yes** [ran]: 187,815 URLs (69,454 phishing, 118,361 benign), 169,947 domains |
| Wired into the system | **Yes**: `detector.py` calls `predict.predict(url)` |
| Quality | **Modest.** AUC 0.866, recall 67%, false-positive rate 8.1% at 0.5 (2.3% at 0.7) [ran]. See section 6 |
| Role in the system | Supporting signal only. It can raise "Suspicious" but never "Malicious" on its own |
| Not done | Run Safe Browsing with a real key (code written and mock-tested), per-URL explanations, Supabase `ai_models` row update, end-to-end test with the extension after the latest retrain |

## 2. What it does

Estimates P(phishing) for a URL from its text alone: host and path. No network calls, no WHOIS, no page content, so it can score URLs that no feed has seen. "Valid or not" means malicious vs benign, not URL syntax.

Honest limit: a phishing page on a normal-looking domain (e.g. `chartersbank.com`, `teramill.com`) looks like any benign site to a lexical model. Only reputation sources (PhishTank, Google Safe Browsing) can catch those.

## 3. Pipeline and files (all in `backend/`, run from there)

```
feeds.py / import_phishtank.py / export_history.py / import_labeled.py   -> data/*
build_dataset.py -> data/dataset.csv -> train.py -> model.joblib + model_metrics.json
extension -> app.py -> detector.py -> predict.py (loads model.joblib, uses features.py)
```

| File | Purpose |
|---|---|
| `features.py` | 29 lexical features. **Shared by training and prediction; never duplicate.** Has `FEATURE_VERSION` (now 3) |
| `train.py` | Group split by domain, metrics, threshold table, root-only check, saves model |
| `predict.py` | `predict(url)` -> dict or `None` (no opinion). Never raises. Refuses a model whose feature names or version differ |
| `build_dataset.py` | Builds the dataset; matches the share of URLs with a path between classes |
| `feeds.py` | Tranco (top 300k domains), OpenPhish, URLhaus |
| `import_phishtank.py` | PhishTank verified feed -> `data/phishing_extra.csv` (tries 4 file formats; needs `PHISHTANK_API_KEY`) |
| `import_labeled.py` | Public labelled CSV -> `data/benign_labeled.csv`, `data/phishing_labeled.csv` |
| `export_history.py` | Own Chrome history -> `data/benign_extra.csv` (query strings removed; keep private) |
| `try_urls.py` | Score a few URLs with the model only |
| `safebrowsing.py` | Google Safe Browsing provider (optional, needs an API key) |
| `detector.py` | Combines blacklist, whitelist, trusted prefixes, PhishTank, Safe Browsing, model, shared-host rule |

## 4. Features (29, feature version 3)

Host (leading `www.` removed): `host_length, num_dots_host, num_hyphens_host, num_digits_host, digit_ratio_host, num_subdomains, host_is_ip, has_at_symbol, risky_tld, host_entropy, has_punycode, longest_host_label, reg_label_length, tld_length, num_host_tokens, avg_token_length, max_consonant_run, vowel_ratio_host, digit_letter_switches, brand_mismatch`

Path (trailing `/` removed): `path_length, num_path_segments, path_special_chars, num_suspicious_words, path_has_risky_ext, path_pct_encoded, path_digit_ratio, longest_path_token, path_double_slash`

Deliberately excluded: scheme (http/https) and the query string. `https://x.com`, `https://x.com/` and `https://www.x.com/` give identical features [tested]. Training and serving must run with the same `tldextract` situation (installed or not).

## 5. Data

| Source | Use | Notes |
|---|---|---|
| OpenPhish + URLhaus (27,586 URLs) | Phishing / malware | URLhaus leans towards malware and IP hosts |
| PhishTank verified feed (63,895 URLs) | Phishing | Only entries still online; licence/terms not checked |
| PhiUSIIL dataset (UCI #967), `label` 1 = legitimate, 0 = phishing | Both | Legitimate and phishing URLs are **homepages only** (no path/query) in the 29-row sample inspected; licence not checked; cite in the report |
| Tranco top 300k | Benign domains with synthetic paths | Not used in the last run (enough real benign URLs) |
| Own Chrome history (60 URLs used) | Benign | Private; never commit |

Rules in `build_dataset.py`: at most 5 phishing and 10 benign URLs per registered domain; domains in the phishing set are removed from the benign set; the share of URLs with a path is matched between classes (0.34 vs 0.34 [ran]) so "has a path" cannot separate the classes.

## 6. Results [ran, 2026-10-15, final feature set and data]

Dataset: 187,815 URLs (69,454 phishing, 118,361 benign), 169,947 domains; share of URLs with a path 0.34 (phishing) vs 0.34 (benign). Group split by registered domain, 80/20.

| Metric | Value |
|---|---|
| accuracy | 0.8255 |
| precision | 0.8289 |
| recall | 0.6674 |
| F1 | 0.7394 |
| ROC-AUC | 0.8658 |
| false-positive rate @0.5 | 0.0813 |

| Threshold | False-positive rate | Recall |
|---|---|---|
| 0.3 | 0.3932 | 0.8475 |
| 0.4 | 0.1675 | 0.7268 |
| 0.5 | 0.0813 | 0.6674 |
| 0.6 | 0.0428 | 0.6239 |
| 0.7 | 0.0227 | 0.5846 |
| 0.8 | 0.0102 | 0.5377 |
| 0.9 | 0.0038 | 0.4569 |

Root-only check (same test URLs reduced to `scheme://host/`): AUC 0.788, false-positive 0.105, recall 0.599. Homepages alone are hard to classify from text.

Top features: host_entropy, risky_tld, num_host_tokens, num_dots_host, path_length.

How the AUC evolved (all [ran]): first model, synthetic benign paths 0.978 (misleadingly good); real data and harder negatives 0.944; after adding PhiUSIIL 0.872; after removing a trailing-slash and `www.` artefact 0.843; after matching path presence 0.839; after adding 13 features 0.873; after adding ID-style benign paths (so Google Docs-style URLs stop looking like phishing) 0.866. The earlier higher numbers came from dataset artefacts, not skill, and the last small drop is the price of removing another shortcut.

## 7. How the detector uses the model (`detector.py`)

1. Blacklist (manual list, OpenPhish/URLhaus feed) -> Malicious 100.
2. Whitelist (manual + Tranco top 10,000, hosts not in `shared_hosts.txt`) -> Safe 5.
3. Trusted prefixes -> Safe 5. Built in: `drive.google.com/drive/` (the signed-in user's own Drive UI); more can be added in `lists/trusted_prefixes.txt`.
4. PhishTank + model: highest score wins, with these rules [tested with mocks]:
   - Model probability is mapped to a score: below 0.7 -> 0..29; 0.7 to 1.0 -> 30..69 (Suspicious). The model alone never reaches Malicious. 0.7 was chosen from the threshold table (about 2% false positives, 60% recall) [judgement].
   - **Agreement rule:** a PhishTank record with score >= 60 (e.g. submitted but not yet voted on) plus a model score in the Suspicious range -> Malicious (70).
   - **No "Safe" without evidence of safety.** If the only evidence is a low model score (and PhishTank has no record), the result is `Unknown` (`has_data` false) with the reason "no strong phishing signal; not a guarantee". Reason: a phishing page on a normal-looking domain (`chartersbank.com`) scores low and must not be shown as safe.
   - `predict()` returning `None` means no opinion, never 0.
   - **Google Safe Browsing** (`safebrowsing.py`, Lookup API v4; inactive unless `GOOGLE_SAFE_BROWSING_API_KEY` is set): a listed URL scores 100 (phishing, malware) or 85 (unwanted software) and is treated like a PhishTank hit. No match, or a failed lookup, is never evidence of safety. The Lookup API sends the full URL to Google: disclose in the report. Mock-tested only; not yet run against the real API [tested].
5. Shared hosting platforms (`lists/shared_hosts.txt`): mild warning (score 30, Suspicious) with an explanation that this does not mean the page is malicious. The model sees only the host there (paths are random document IDs); PhishTank domain-level matches are ignored; an exact PhishTank match still gives Malicious.

Result fields consumed by the extension are unchanged. Mapping to the database: `probability` -> `detection_results.confidence`, `model_version` -> `model_id`, `top_features` -> `result_details` (global top features with this URL's raw values, **not** a per-URL attribution).

## 8. Known weaknesses

1. **Lexical ceiling.** About one third of phishing is missed at the chosen threshold, and benign sites on unusual domains get flagged about 2% of the time.
2. **Benign paths are partly synthetic and homepage-heavy.** Real benign URLs come mostly from a homepage-only dataset; the path-presence matching removes the "has a path" shortcut, but path-shape features are still trained on thin real evidence. The test figures are probably optimistic for deep links.
3. **Not time-split.** The split is by domain, not by date. New campaigns will score lower than the test set suggests.
4. **`brand_mismatch` can false-positive** on legitimate domains that contain a brand name (e.g. user-content domains); the whitelist covers the big ones.
5. **Long random IDs in paths** (document links, file IDs) looked like phishing to the first 29-feature model (observed: Google Docs URL scored 97%). Mitigated by host-only scoring on shared platforms and by ID-style benign path templates in `build_dataset.py`; needs a retrain and re-test.
6. **Unvalidated end to end.** Latest feature set not yet re-tested in the extension on the known cases (`phishtank.net`, `p581488.pro`, `drive.google.com`, `chartersbank.com`).
7. Licences of PhishTank, OpenPhish, URLhaus and PhiUSIIL not checked; cite them in the report.
8. The thesis text should say 29 lexical features if it gives a count.

## 9. How to retrain (from `backend/`, venv active)

```
python feeds.py
python import_phishtank.py                 # optional, needs PHISHTANK_API_KEY
python export_history.py                   # optional
python import_labeled.py <csv> --url-col URL --label-col label --benign-value 1   # optional
python build_dataset.py
python train.py
```
Re-run `train.py` after any change to `features.py`; an old `model.joblib` is refused automatically.

## 10. Suggested next steps

1. Re-test the known cases in the extension and record the scores.
2. Set a Safe Browsing API key and confirm `chartersbank.com` is caught (code is written).
3. Build a small hand-labelled test set (about 50 sites you use, 50 recent phishing URLs not in the training data) and measure on it.
4. Add a time-based evaluation.
5. Write metrics into `ai_models.metrics` and activate the row once the model is accepted.
6. If someone other than the student contributes the ML part, confirm credit with the supervisor (thesis section 1.5 lists one member).
