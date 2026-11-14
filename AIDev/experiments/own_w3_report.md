# Content model results: own_w3

- evaluation mode: own-pages-test
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --test-on own --own-weight 3 --out own_w3
- pages: train 12463, validation 2054, test 1113 (test phishing 267, benign 846, campaigns 995)
- campaigns: 11737 clusters from 13898 domains; 487 span several domains (2161 domains merged away); largest cluster [199, 127, 89] pages; mixed-label clusters 87
- training cap 20: 613 of 12463 training pages removed in 20 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.9115

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.6258 | [0.5493, 0.6967] |
| roc_auc (raw probability) | 0.8081 | [0.7656, 0.8440] |
| recall@fpr1% (raw probability) | 0.1423 | [0.0920, 0.2519] |
| recall@fpr0.5% (raw probability) | 0.1348 | [0.0451, 0.1898] |
| accuracy at probability 0.5 (comparable with the old reports) | 0.8176 | [0.7839, 0.8475] |
| recall at probability 0.5 (comparable with the old reports) | 0.5581 | [0.4800, 0.6265] |
| false-positive rate at probability 0.5 (comparable with the old reports) | 0.1005 | [0.0675, 0.1410] |
| precision at probability 0.5 (comparable with the old reports) | 0.6368 | [0.5485, 0.7256] |
| brier (raw) | 0.1394 | [0.1251, 0.1547] |
| brier (calibrated) | 0.1484 | [0.1279, 0.1716] |
| ece (raw) | 0.0669 | [0.0514, 0.0955] |
| ece (calibrated) | 0.0895 | [0.0662, 0.1224] |
| fixed_recall at validation threshold (calibrated) | 0.1348 | [0.0878, 0.1849] |
| fixed_fpr at validation threshold (calibrated) | 0.0047 | [0.0012, 0.0096] |
| fixed_precision at validation threshold (calibrated) | 0.9000 | [0.7949, 0.9778] |

False-positive rate / recall per source at the validation threshold:

| source | pages | FPR | recall |
|---|---|---|---|
| benign_history | 1 | 0.0000 | nan |
| benign_tail | 507 | 0.0039 | nan |
| benign_tail_login | 67 | 0.0149 | nan |
| benign_top | 237 | 0.0042 | nan |
| benign_top_login | 34 | 0.0000 | nan |
| phish_feed | 267 | nan | 0.1348 |

- NOTE: recall@fpr0.5%: only 4 false positives allowed in this test set; treat as rough
