# Content model results: m2_v3_hgb_own

- evaluation mode: own-pages-test
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --model hgb --test-on own --out m2_v3_hgb_own
- pages: train 12463, validation 2054, test 1113 (test phishing 267, benign 846, campaigns 995)
- campaigns: 11737 clusters from 13898 domains; 487 span several domains (2161 domains merged away); largest cluster [199, 127, 89] pages; mixed-label clusters 87
- training cap 20: 613 of 12463 training pages removed in 20 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.8696

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.5979 | [0.5206, 0.6687] |
| roc_auc (raw probability) | 0.7919 | [0.7496, 0.8283] |
| recall@fpr1% (raw probability) | 0.1386 | [0.0717, 0.2521] |
| recall@fpr0.5% (raw probability) | 0.1086 | [0.0259, 0.2031] |
| brier (raw) | 0.1557 | [0.1383, 0.1737] |
| brier (calibrated) | 0.1590 | [0.1412, 0.1772] |
| ece (raw) | 0.1046 | [0.0818, 0.1362] |
| ece (calibrated) | 0.1105 | [0.0855, 0.1396] |
| fixed_recall at validation threshold (calibrated) | 0.2397 | [0.1789, 0.3042] |
| fixed_fpr at validation threshold (calibrated) | 0.0213 | [0.0119, 0.0318] |
| fixed_precision at validation threshold (calibrated) | 0.7805 | [0.6747, 0.8718] |

False-positive rate / recall per source at the validation threshold:

| source | pages | FPR | recall |
|---|---|---|---|
| benign_history | 1 | 0.0000 | nan |
| benign_tail | 507 | 0.0197 | nan |
| benign_tail_login | 67 | 0.0896 | nan |
| benign_top | 237 | 0.0084 | nan |
| benign_top_login | 34 | 0.0000 | nan |
| phish_feed | 267 | nan | 0.2397 |

- NOTE: recall@fpr0.5%: only 4 false positives allowed in this test set; treat as rough
