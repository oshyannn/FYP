# Clone diagnostic experiments/m2_v3_own_preds.csv

- official reference pages used: 834 (sources: benign_top, benign_top_login)
- content-model threshold (1% FPR on the test set): 0.8529
- similarity = Jaccard of 5-tag windows of the DOM tag sequence, best match among official pages of OTHER domains

## Background: how similar are ordinary benign pages to official pages by chance?

| benign pages sampled | median | p90 | p95 | p99 (= clone cut-off) |
|---|---|---|---|---|
| 532 | 0.099 | 0.161 | 0.349 | 1.000 |

## How many pages pass the clone cut-off?

| group | pages | unreadable | sim >= cut | share | sim >= 0.5 | sim >= 0.7 | sim >= 0.85 |
|---|---|---|---|---|---|---|---|
| missed phishing (below threshold) | 232 | 0 | 0 | 0.0% | 4 (2.5%) | 3 (1.9%) | 0 (0.0%) |
| caught phishing (at or above threshold) | 35 | 0 | 0 | 0.0% | 0 (0.0%) | 0 (0.0%) | 0 (0.0%) |
| benign (background) | 600 | 0 | 12 | 2.3% | 22 (4.1%) | 17 (3.2%) | 15 (2.8%) |

## Missed phishing pages that look like a copy of an official page (top 30, URLs defanged: do NOT open)

None above the cut-off.

## Reading the result

- Missed phishing pages above the clone cut-off: 0.0%. Caught phishing pages above it: 0.0%.
- Only a small share of the misses are clones, so an overlap check alone will not fix most of them. Look at the other causes in the error analysis (tiny pages, shortener and form-builder platforms).
