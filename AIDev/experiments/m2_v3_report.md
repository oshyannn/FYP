# Content model results: m2_v3

- evaluation mode: random-campaign-split
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --out m2_v3 --ablate
- pages: train 10932, validation 1863, test 3085 (test phishing 1330, benign 1755, campaigns 2347)
- campaigns: 11737 clusters from 13898 domains; 487 span several domains (2161 domains merged away); largest cluster [199, 127, 89] pages; mixed-label clusters 87
- training cap 20: 544 of 10932 training pages removed in 19 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.8743

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.9384 | [0.9153, 0.9568] |
| roc_auc (raw probability) | 0.9441 | [0.9294, 0.9557] |
| recall@fpr1% (raw probability) | 0.5383 | [0.4587, 0.6414] |
| recall@fpr0.5% (raw probability) | 0.4962 | [0.3990, 0.5806] |
| brier (raw) | 0.0936 | [0.0845, 0.1037] |
| brier (calibrated) | 0.0918 | [0.0811, 0.1038] |
| ece (raw) | 0.0477 | [0.0374, 0.0637] |
| ece (calibrated) | 0.0187 | [0.0127, 0.0361] |
| fixed_recall at validation threshold (calibrated) | 0.3985 | [0.3191, 0.4810] |
| fixed_fpr at validation threshold (calibrated) | 0.0000 | [0.0000, 0.0000] |
| fixed_precision at validation threshold (calibrated) | 1.0000 | [1.0000, 1.0000] |

False-positive rate / recall per source at the validation threshold:

| source | pages | FPR | recall |
|---|---|---|---|
| benign_tail | 344 | 0.0000 | nan |
| benign_tail_login | 41 | 0.0000 | nan |
| benign_top | 147 | 0.0000 | nan |
| benign_top_login | 26 | 0.0000 | nan |
| phish_feed | 190 | nan | 0.0053 |
| phreshphish_benign | 1197 | 0.0000 | nan |
| phreshphish_phish | 1140 | nan | 0.4640 |

## Ablation by feature group (group removed, same split, raw probabilities)

| removed group | features left | PR-AUC [95% CI] | recall @1% FPR [95% CI] |
|---|---|---|---|
| (none, all features) | 53 | 0.9384 [0.9154, 0.9578] | 0.5383 [0.4588, 0.6427] |
| forms | 39 | 0.9355 [0.9116, 0.9554] | 0.5293 [0.4394, 0.6215] |
| brand_title | 43 | 0.9253 [0.8988, 0.9481] | 0.5383 [0.4233, 0.6263] |
| links_resources | 42 | 0.9253 [0.8982, 0.9488] | 0.5316 [0.4489, 0.6157] |
| scripts | 43 | 0.9378 [0.9143, 0.9584] | 0.5737 [0.4728, 0.6555] |
| size_text | 45 | 0.9362 [0.9131, 0.9555] | 0.5466 [0.4456, 0.6437] |
