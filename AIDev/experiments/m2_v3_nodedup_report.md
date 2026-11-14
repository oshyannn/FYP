# Content model results: m2_v3_nodedup

- evaluation mode: random-campaign-split-no-dedup
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --no-dedup --out m2_v3_nodedup
- pages: train 10806, validation 1916, test 3158 (test phishing 1373, benign 1785, campaigns 2780)
- campaigns: 13898 clusters from 13898 domains; 0 span several domains (0 domains merged away); largest cluster [] pages; mixed-label clusters n/a
- training cap 0: 0 of 10806 training pages removed in 0 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.8714

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.9466 | [0.9381, 0.9550] |
| roc_auc (raw probability) | 0.9514 | [0.9434, 0.9588] |
| recall@fpr1% (raw probability) | 0.6169 | [0.5629, 0.6686] |
| recall@fpr0.5% (raw probability) | 0.5412 | [0.4859, 0.6207] |
| brier (raw) | 0.0878 | [0.0818, 0.0934] |
| brier (calibrated) | 0.0848 | [0.0783, 0.0913] |
| ece (raw) | 0.0450 | [0.0379, 0.0568] |
| ece (calibrated) | 0.0159 | [0.0113, 0.0288] |
| fixed_recall at validation threshold (calibrated) | 0.5208 | [0.4932, 0.5510] |
| fixed_fpr at validation threshold (calibrated) | 0.0034 | [0.0011, 0.0062] |
| fixed_precision at validation threshold (calibrated) | 0.9917 | [0.9844, 0.9973] |

False-positive rate / recall per source at the validation threshold:

| source | pages | FPR | recall |
|---|---|---|---|
| benign_tail | 328 | 0.0091 | nan |
| benign_tail_login | 48 | 0.0208 | nan |
| benign_top | 168 | 0.0000 | nan |
| benign_top_login | 19 | 0.0000 | nan |
| phish_feed | 210 | nan | 0.1524 |
| phreshphish_benign | 1222 | 0.0016 | nan |
| phreshphish_phish | 1163 | nan | 0.5873 |
