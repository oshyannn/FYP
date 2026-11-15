# Content model results: m2_v3_final

- evaluation mode: random-campaign-split
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --out m2_v3_final
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
| accuracy at probability 0.5 (comparable with the old reports) | 0.8765 | [0.8577, 0.8933] |
| recall at probability 0.5 (comparable with the old reports) | 0.8023 | [0.7587, 0.8418] |
| false-positive rate at probability 0.5 (comparable with the old reports) | 0.0672 | [0.0551, 0.0795] |
| precision at probability 0.5 (comparable with the old reports) | 0.9004 | [0.8738, 0.9240] |
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

## Exploratory: phishing pages on platform / shortener domains left out

Rule fixed after the first error analysis (domain with at least 5 phishing pages in the data; 0 such domains); 0 test pages excluded. Report next to, never instead of, the table above.

| metric (raw probability) | value | 95% CI |
|---|---|---|
| pr_auc | 0.9384 | [0.9154, 0.9578] |
| roc_auc | 0.9441 | [0.9310, 0.9562] |
| recall@fpr1% | 0.5383 | [0.4588, 0.6427] |
| t0.5_accuracy | 0.8765 | [0.8574, 0.8929] |
| t0.5_recall | 0.8023 | [0.7594, 0.8418] |
| t0.5_fpr | 0.0672 | [0.0554, 0.0796] |
