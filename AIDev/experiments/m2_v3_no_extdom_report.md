# Content model results: m2_v3_no_extdom

- evaluation mode: random-campaign-split
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid,n_ext_domains --out m2_v3_no_extdom
- pages: train 10932, validation 1863, test 3085 (test phishing 1330, benign 1755, campaigns 2347)
- campaigns: 11737 clusters from 13898 domains; 487 span several domains (2161 domains merged away); largest cluster [199, 127, 89] pages; mixed-label clusters 87
- training cap 20: 544 of 10932 training pages removed in 19 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.8836

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.9377 | [0.9151, 0.9558] |
| roc_auc (raw probability) | 0.9426 | [0.9282, 0.9546] |
| recall@fpr1% (raw probability) | 0.5827 | [0.4692, 0.6553] |
| recall@fpr0.5% (raw probability) | 0.4977 | [0.4077, 0.5927] |
| brier (raw) | 0.0946 | [0.0850, 0.1048] |
| brier (calibrated) | 0.0919 | [0.0814, 0.1031] |
| ece (raw) | 0.0500 | [0.0406, 0.0670] |
| ece (calibrated) | 0.0136 | [0.0094, 0.0319] |
| fixed_recall at validation threshold (calibrated) | 0.3729 | [0.2881, 0.4601] |
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
| phreshphish_phish | 1140 | nan | 0.4342 |
