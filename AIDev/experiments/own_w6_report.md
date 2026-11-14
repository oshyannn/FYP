# Content model results: own_w6

- evaluation mode: own-pages-test
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --test-on own --own-weight 6 --out own_w6
- pages: train 12463, validation 2054, test 1113 (test phishing 267, benign 846, campaigns 995)
- campaigns: 11737 clusters from 13898 domains; 487 span several domains (2161 domains merged away); largest cluster [199, 127, 89] pages; mixed-label clusters 87
- training cap 20: 613 of 12463 training pages removed in 20 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.8982

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.6224 | [0.5419, 0.6976] |
| roc_auc (raw probability) | 0.8109 | [0.7702, 0.8461] |
| recall@fpr1% (raw probability) | 0.1498 | [0.0947, 0.2365] |
| recall@fpr0.5% (raw probability) | 0.1124 | [0.0453, 0.1934] |
| accuracy at probability 0.5 (comparable with the old reports) | 0.8158 | [0.7833, 0.8459] |
| recall at probability 0.5 (comparable with the old reports) | 0.5655 | [0.4886, 0.6351] |
| false-positive rate at probability 0.5 (comparable with the old reports) | 0.1052 | [0.0718, 0.1467] |
| precision at probability 0.5 (comparable with the old reports) | 0.6292 | [0.5404, 0.7156] |
| brier (raw) | 0.1386 | [0.1236, 0.1555] |
| brier (calibrated) | 0.1464 | [0.1264, 0.1702] |
| ece (raw) | 0.0614 | [0.0482, 0.0919] |
| ece (calibrated) | 0.0980 | [0.0714, 0.1297] |
| fixed_recall at validation threshold (calibrated) | 0.1124 | [0.0738, 0.1591] |
| fixed_fpr at validation threshold (calibrated) | 0.0047 | [0.0012, 0.0096] |
| fixed_precision at validation threshold (calibrated) | 0.8824 | [0.7647, 0.9737] |

False-positive rate / recall per source at the validation threshold:

| source | pages | FPR | recall |
|---|---|---|---|
| benign_history | 1 | 0.0000 | nan |
| benign_tail | 507 | 0.0039 | nan |
| benign_tail_login | 67 | 0.0149 | nan |
| benign_top | 237 | 0.0042 | nan |
| benign_top_login | 34 | 0.0000 | nan |
| phish_feed | 267 | nan | 0.1124 |

- NOTE: recall@fpr0.5%: only 4 false positives allowed in this test set; treat as rough
