# Content model results: m2_v2

- evaluation mode: random-campaign-split
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --only-v2 --out m2_v2
- pages: train 10932, validation 1863, test 3085 (test phishing 1330, benign 1755, campaigns 2347)
- campaigns: 11737 clusters from 13898 domains; 487 span several domains (2161 domains merged away); largest cluster [199, 127, 89] pages; mixed-label clusters 87
- training cap 20: 544 of 10932 training pages removed in 19 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.8757

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.9373 | [0.9140, 0.9558] |
| roc_auc (raw probability) | 0.9427 | [0.9282, 0.9546] |
| recall@fpr1% (raw probability) | 0.5797 | [0.4803, 0.6504] |
| recall@fpr0.5% (raw probability) | 0.5226 | [0.3901, 0.6043] |
| brier (raw) | 0.0951 | [0.0857, 0.1051] |
| brier (calibrated) | 0.0933 | [0.0831, 0.1044] |
| ece (raw) | 0.0514 | [0.0414, 0.0677] |
| ece (calibrated) | 0.0256 | [0.0168, 0.0420] |
| fixed_recall at validation threshold (calibrated) | 0.3654 | [0.2849, 0.4509] |
| fixed_fpr at validation threshold (calibrated) | 0.0011 | [0.0000, 0.0035] |
| fixed_precision at validation threshold (calibrated) | 0.9959 | [0.9853, 1.0000] |

False-positive rate / recall per source at the validation threshold:

| source | pages | FPR | recall |
|---|---|---|---|
| benign_tail | 344 | 0.0000 | nan |
| benign_tail_login | 41 | 0.0000 | nan |
| benign_top | 147 | 0.0000 | nan |
| benign_top_login | 26 | 0.0000 | nan |
| phish_feed | 190 | nan | 0.0053 |
| phreshphish_benign | 1197 | 0.0017 | nan |
| phreshphish_phish | 1140 | nan | 0.4254 |
