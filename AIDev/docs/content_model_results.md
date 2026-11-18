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

Accuracy at probability 0.5 (the operating point of the first, uncorrected report), campaign split: accuracy 0.877 [0.858, 0.893],
recall 0.802, false-positive rate 6.7%, precision 0.900. Own pages only: accuracy 0.810, recall 0.569, false-positive rate 11.5%,
precision 0.610. The final re-runs (`m2_v3_final`, `m2_v3_own_final`, seed 42) reproduced every number above exactly.

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

## 10. Own-crawl pages: what goes wrong (error analysis at the 1% false-positive point)

Own-pages test (267 phishing, 846 benign): 232 of 267 phishing pages missed (86.9%), 8 benign pages flagged (0.9%).

| why the phishing page was missed | pages | share |
|---|---|---|
| tiny page: almost no text (< 30 words) | 97 | 41.8% |
| no form at all (landing / lure page) | 55 | 23.7% |
| has a form, nothing sensitive | 53 | 22.8% |
| redirector page (meta refresh / JavaScript) | 21 | 9.1% |
| credential form, no other strong signal | 6 | 2.6% |

Benign pages wrongly flagged: 62.5% (own pages) and 76.5% (mixed test) are also tiny pages. Many missed own-crawl phishing URLs are
link shorteners (`qrco.de`, `l.ead.me`, `1sh.co`, `ezurl.nl`), redirect pages (`vk.com/away.php`) or pages on legitimate form /
page-builder platforms (`jotform`, `surveysparrow`, `plutio`, `kobotoolbox`): the saved HTML is the platform's own page, and the
phishing is only at the destination. A static page-content model cannot see it; the label belongs to the URL, not to the saved page.

## 11. Weighting pages crawled by ourselves (`--own-weight`), own-pages test, seed 42

| run | PR-AUC | ROC-AUC | recall at 1% FPR | accuracy / recall / FPR at probability 0.5 | recall / FPR at validation threshold |
|---|---|---|---|---|---|
| weight 1 | 0.610 [0.532, 0.683] | 0.794 | 0.131 | 0.810 / 0.569 / 0.115 | 0.266 / 0.020 |
| weight 3 | 0.626 [0.549, 0.697] | 0.808 | 0.142 | 0.818 / 0.558 / 0.100 | 0.135 / 0.005 |
| weight 6 | 0.622 [0.542, 0.698] | 0.811 | 0.150 | 0.816 / 0.566 / 0.105 | 0.112 / 0.005 |

Weighting gives a small gain in ranking (ROC-AUC 0.794 -> 0.808) that is far inside the confidence intervals (about +-0.07): not
a demonstrated improvement. `--val-own-only` does not change the model, only calibration and threshold; the resulting threshold
keeps the false-positive rate at 0.5% (target 1%) and recall at 0.11. For comparison with the first, uncorrected report: accuracy
at probability 0.5 is 0.81-0.82 on own pages (the original 0.88 was measured on the mixed split).

## 12. Limits (state in the report)

- Platform/shortener rule (exploratory; defined after the first error analysis, so not a clean test). A domain with at least 5
  phishing pages in the data is a platform; the rule uses the SUBMITTED host (`url_domain`), not `group` (the landing domain;
  the first version used `group` and excluded 0 pages). Test pages without the phishing pages on such domains:

  | test | phishing pages removed | PR-AUC | ROC-AUC | recall at 1% FPR | accuracy at 0.5 |
  |---|---|---|---|---|---|
  | campaign split, all pages | 0 | 0.938 | 0.944 | 0.538 | 0.877 |
  | campaign split, without platform phishing | 57 of 1,330 | 0.946 | 0.954 | 0.561 | 0.888 |
  | own pages, all pages | 0 | 0.610 | 0.794 | 0.131 | 0.810 |
  | own pages, without platform phishing | 65 of 267 | 0.633 | 0.856 | 0.173 | 0.843 |

  Removing phishing pages changes the class balance, so PR-AUC is not comparable between rows. Even without these pages, recall
  at 1% false positives on own pages is only 0.17: platform pages explain part of the weakness, not all of it.
- Static HTML only: content built by JavaScript and cloaked pages are not seen. Headless rendering, screenshot similarity and
  re-crawling are future work.
- Part of the own-crawl phishing pages are on shared platforms or link shorteners, where the saved page is the platform's own
  page; this is label noise (87 mixed-label campaigns).
- The saved model is fitted on train + test (without the validation part); the numbers above come from the train-only fit.
- Recall at 0.1% false-positive rate is not reported: a few thousand test pages cannot measure it.
