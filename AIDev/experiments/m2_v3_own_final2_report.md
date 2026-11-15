# Content model results: m2_v3_own_final2

- evaluation mode: own-pages-test
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --test-on own --out m2_v3_own_final2
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
| accuracy at probability 0.5 (comparable with the old reports) | 0.8095 | [0.7776, 0.8400] |
| recall at probability 0.5 (comparable with the old reports) | 0.5693 | [0.4917, 0.6358] |
| false-positive rate at probability 0.5 (comparable with the old reports) | 0.1147 | [0.0815, 0.1554] |
| precision at probability 0.5 (comparable with the old reports) | 0.6104 | [0.5274, 0.6939] |
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

## Exploratory: phishing pages on platform / shortener domains left out

Rule fixed after the first error analysis (domain with at least 5 phishing pages in the data; 8 such domains); 65 test pages excluded. Report next to, never instead of, the table above.

| metric (raw probability) | value | 95% CI |
|---|---|---|
| pr_auc | 0.6329 | [0.5574, 0.7150] |
| roc_auc | 0.8559 | [0.8214, 0.8881] |
| recall@fpr1% | 0.1733 | [0.1070, 0.2973] |
| t0.5_accuracy | 0.8426 | [0.8117, 0.8696] |
| t0.5_recall | 0.6634 | [0.5937, 0.7343] |
| t0.5_fpr | 0.1147 | [0.0838, 0.1533] |
