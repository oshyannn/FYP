# Content model results: m2_v3_own

- evaluation mode: own-pages-test
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --test-on own --out m2_v3_own
- pages: train 12463, validation 2054, test 1113 (test phishing 267, benign 846, campaigns 995)
- campaigns: 11737 clusters from 13898 domains; 487 span several domains (2161 domains merged away); largest cluster [199, 127, 89] pages; mixed-label clusters 87
- training cap 20: 613 of 12463 training pages removed in 20 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.8642

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.6102 | [0.5324, 0.6826] |
| roc_auc (raw probability) | 0.7939 | [0.7507, 0.8316] |
| recall@fpr1% (raw probability) | 0.1311 | [0.0811, 0.2500] |
| recall@fpr0.5% (raw probability) | 0.1049 | [0.0347, 0.1754] |
| brier (raw) | 0.1462 | [0.1315, 0.1614] |
| brier (calibrated) | 0.1537 | [0.1333, 0.1755] |
| ece (raw) | 0.0851 | [0.0650, 0.1123] |
| ece (calibrated) | 0.1035 | [0.0760, 0.1343] |
| fixed_recall at validation threshold (calibrated) | 0.2659 | [0.2033, 0.3297] |
| fixed_fpr at validation threshold (calibrated) | 0.0201 | [0.0106, 0.0303] |
| fixed_precision at validation threshold (calibrated) | 0.8068 | [0.7083, 0.8933] |

False-positive rate / recall per source at the validation threshold:

| source | pages | FPR | recall |
|---|---|---|---|
| benign_history | 1 | 0.0000 | nan |
| benign_tail | 507 | 0.0178 | nan |
| benign_tail_login | 67 | 0.0746 | nan |
| benign_top | 237 | 0.0084 | nan |
| benign_top_login | 34 | 0.0294 | nan |
| phish_feed | 267 | nan | 0.2659 |

- NOTE: recall@fpr0.5%: only 4 false positives allowed in this test set; treat as rough
