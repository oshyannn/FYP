# Page-content model (model 2): evaluation results, 2026-11-14

Data: `data/pages` = 15,880 pages (phishing 7,016, benign 8,864) from 13,898 domains. Sources: own crawl (`phish_feed`,
`benign_top`, `benign_top_login`, `benign_tail`, `benign_tail_login`, `benign_history`) and PhreshPhish (`phreshphish_phish`,
`phreshphish_benign`). Features: 53 (the 3 redirect/TLS collection artefacts dropped). All intervals are 95% intervals from a
bootstrap that resamples whole campaigns.

## 1. Campaigns (step C)

15,880 pages -> 11,737 campaigns. 487 campaigns span several domains (2,161 domains merged away); the largest has 199 pages
(1.3% of all pages); 553 pages had too little structure for a fingerprint; 87 campaigns contain both classes (label noise or
generic templates). Training cap of 20 pages per campaign removed 544 of 10,932 training pages (19 campaigns).

## 2. Same model, three ways of testing

| test | pages (test) | PR-AUC | ROC-AUC | recall at 1% false-positive rate |
|---|---|---|---|---|
| old style: split by domain only, no cap (`m2_v3_nodedup`) | 3,158 | 0.947 [0.938, 0.955] | 0.951 | 0.617 [0.563, 0.669] |
| split by campaign (`m2_v3`) | 3,085 | 0.938 [0.915, 0.957] | 0.944 [0.929, 0.956] | 0.538 [0.459, 0.641] |
| only pages crawled by ourselves, by campaign (`m2_v3_own`) | 1,113 | 0.610 [0.532, 0.683] | 0.794 [0.751, 0.832] | 0.131 [0.081, 0.250] |

The old-style split is a little more optimistic than the campaign split, but the two test sets differ and the intervals
overlap, so this is a direction, not proof. The large gap is between the first two rows and the last: on pages like the ones
the live detector fetches, the model is much weaker than the headline numbers. The first two rows are dominated by PhreshPhish
pages (2,337 of 3,085 test pages), the third contains none.

## 3. Are the new features (version 3) useful?

| model | PR-AUC | ROC-AUC | recall at 1% FPR |
|---|---|---|---|
| version 2 features only (47) (`m2_v2`) | 0.937 [0.914, 0.956] | 0.943 | 0.580 [0.480, 0.650] |
| version 3 features (53) (`m2_v3`) | 0.938 [0.915, 0.957] | 0.944 | 0.538 [0.459, 0.641] |
| version 3 without `n_ext_domains` (52) (`m2_v3_no_extdom`) | 0.938 [0.915, 0.956] | 0.943 | 0.583 [0.469, 0.655] |

With the old script and split: version 2 AUC 0.945, version 3 AUC 0.946. No measurable gain from the six new features on this
data. `n_ext_domains` is the most important feature by Random-Forest importance (0.106) yet removing it changes nothing: other
features carry the same information, so importance ranking must not be read as necessity.

## 4. Ablation by feature group (campaign split, group removed, raw probability)

| removed | features left | PR-AUC | recall at 1% FPR |
|---|---|---|---|
| none | 53 | 0.9384 | 0.538 |
| forms | 39 | 0.9355 | 0.529 |
| brand / title / words | 43 | 0.9253 | 0.538 |
| links / resources | 42 | 0.9253 | 0.532 |
| scripts | 43 | 0.9378 | 0.574 |
| size / text | 45 | 0.9362 | 0.547 |

Largest drops (about 0.013 PR-AUC) for brand/title and links/resources; scripts hardly matter. Confidence intervals are about
+-0.02 wide (see `experiments/m2_v3_report.md`), so no single group is shown to be essential: the groups overlap.

## 5. Calibration and decision threshold

| | Brier raw -> calibrated | ECE raw -> calibrated | threshold (validation, 1% FPR) | recall on test | false-positive rate on test |
|---|---|---|---|---|---|
| campaign split | 0.0936 -> 0.0918 | 0.048 -> 0.019 | 0.874 | 0.399 [0.319, 0.481] | 0.0% |
| own pages | 0.1462 -> 0.1537 | 0.085 -> 0.104 | 0.864 | 0.266 [0.203, 0.330] | 2.0% [1.1%, 3.0%] |

Isotonic calibration makes probabilities honest on the mixed test (ECE 0.048 -> 0.019) but not on own pages (ECE gets worse).
The threshold picked on mixed validation data held the false-positive rate at 0% on the mixed test but gave 2.0% on own pages
(7.5% on `benign_tail_login`), twice the 1% target. A threshold for the live system should be chosen on pages that look like
the live ones.

## 6. Where the model is weak

At the 1% FPR point of the campaign split, recall is 0.595 on `phreshphish_phish` but only 0.200 on `phish_feed` (own crawl).
Highest false-positive rates are on `benign_tail_login` (small sites' login pages). See `experiments/*_errors.md`
(`error_analysis.py`) for causes.

## 7. Why the new features did not help: how often they fire

Share of pages where the feature is non-zero (all 15,880 pages):

| feature | phishing | benign | what it says |
|---|---|---|---|
| `brand_asset_hotlink` | 6.7% | 12.3% | wrong direction: benign pages hotlink brand pictures / style sheets more often (social icons, partner logos) |
| `brand_in_logo_alt` | 10.7% | 19.4% | wrong direction: app-store badges, "sign in with Google" buttons |
| `brand_in_meta` | 5.8% | 2.1% | right direction (about 3x), but rare |
| `login_form_no_own_links` | 11.2% | 2.3% | right direction (about 5x), rare; PhreshPhish 12.4% vs 3.2%, own crawl 3.6% vs about 0.5% |
| `form_posts_to_ip_or_http` | 0.2% | 0.2% | almost never fires: useless on this data |
| `n_ext_domains` (> 0) | 79% | 95% | benign pages talk to more outside domains |

The hypothesis "a cloned page hotlinks the real brand's assets" is not supported by this data. Two of the six features carry a
real but rare signal, two point the wrong way, one never fires. This matches the null result in section 3.

## 8. Random Forest or gradient boosting?

Same split, same features, same evaluation (`--model hgb`, scikit-learn HistGradientBoostingClassifier):

| test | model | PR-AUC | ROC-AUC | recall at 1% FPR | raw ECE |
|---|---|---|---|---|---|
| campaign split | Random Forest | 0.938 [0.915, 0.957] | 0.944 | 0.538 [0.459, 0.641] | 0.048 |
| campaign split | gradient boosting | 0.940 [0.917, 0.958] | 0.946 | 0.582 [0.484, 0.652] | 0.018 |
| own pages | Random Forest | 0.610 [0.532, 0.683] | 0.794 | 0.131 [0.081, 0.250] | 0.085 |
| own pages | gradient boosting | 0.598 [0.521, 0.669] | 0.792 | 0.139 [0.072, 0.252] | 0.105 |

No significant difference in ranking quality. Gradient boosting is better calibrated out of the box on the mixed test, and
its validation threshold transferred well there (recall 0.573 [0.499, 0.640] at false-positive rate 0.9% [0.5%, 1.4%]); on own
pages the same threshold gives recall 0.240 at 2.1% false positives. The weakness on own pages does not depend on the model type.

## 9. Data composition

Own crawl: 1,021 phishing pages (`phish_feed`) and 3,000 benign pages; PhreshPhish: 6,000 phishing and 6,000 benign. Own-crawled
phishing pages are only 6.5% of all pages, which is one reason for the weak result on pages that look like the live ones
(see `--own-weight` and `--val-own-only` in `train_content2.py`).

## 10. Limits (state in the report)

- Static HTML only: content built by JavaScript and cloaked pages are not seen. Headless rendering, screenshot similarity and
  re-crawling are future work.
- Part of the own-crawl phishing pages are on shared platforms or link shorteners, where the saved page is the platform's own
  page; this is label noise (87 mixed-label campaigns).
- The saved model is fitted on train + test (without the validation part); the numbers above come from the train-only fit.
- Recall at 0.1% false-positive rate is not reported: a few thousand test pages cannot measure it.
