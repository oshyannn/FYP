# Content model results: m2_v3_hgb

- evaluation mode: random-campaign-split
- command options: --drop n_redirects,redirect_cross_domain,tls_invalid --model hgb --out m2_v3_hgb
- pages: train 10932, validation 1863, test 3085 (test phishing 1330, benign 1755, campaigns 2347)
- campaigns: 11737 clusters from 13898 domains; 487 span several domains (2161 domains merged away); largest cluster [199, 127, 89] pages; mixed-label clusters 87
- training cap 20: 544 of 10932 training pages removed in 19 clusters
- decision threshold (calibrated probability, FPR <= 1% on validation): 0.7143

## Test results (95% CI: bootstrap over campaigns)

| metric | value | 95% CI |
|---|---|---|
| pr_auc (raw probability) | 0.9399 | [0.9171, 0.9576] |
| roc_auc (raw probability) | 0.9455 | [0.9316, 0.9569] |
| recall@fpr1% (raw probability) | 0.5820 | [0.4842, 0.6524] |
| recall@fpr0.5% (raw probability) | 0.5180 | [0.4468, 0.6041] |
| brier (raw) | 0.0903 | [0.0800, 0.1006] |
| brier (calibrated) | 0.0905 | [0.0811, 0.1006] |
| ece (raw) | 0.0182 | [0.0137, 0.0359] |
| ece (calibrated) | 0.0173 | [0.0151, 0.0357] |
| fixed_recall at validation threshold (calibrated) | 0.5729 | [0.4991, 0.6404] |
| fixed_fpr at validation threshold (calibrated) | 0.0091 | [0.0047, 0.0142] |
| fixed_precision at validation threshold (calibrated) | 0.9794 | [0.9650, 0.9895] |

False-positive rate / recall per source at the validation threshold:

| source | pages | FPR | recall |
|---|---|---|---|
| benign_tail | 344 | 0.0203 | nan |
| benign_tail_login | 41 | 0.0000 | nan |
| benign_top | 147 | 0.0068 | nan |
| benign_top_login | 26 | 0.0000 | nan |
| phish_feed | 190 | nan | 0.1632 |
| phreshphish_benign | 1197 | 0.0067 | nan |
| phreshphish_phish | 1140 | nan | 0.6412 |
