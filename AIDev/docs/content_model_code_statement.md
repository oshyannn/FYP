# Code source statement: page-content model (model 2) improvements

Written by the project author for this work (own code, written from scratch):
- `aidev/evaluation/eval_content_own.py`: PR-AUC, ROC-AUC, recall at fixed false-positive rate, Brier score, calibration error,
  per-source rates, bootstrap confidence intervals resampled by campaign.
- `aidev/evaluation/campaign_dedup.py`: structure fingerprint of an HTML page, campaign clustering (union-find over
  domain/fingerprint), per-campaign cap for training.
- `aidev/pipeline_own2/train_content2.py`: campaign-wise train/validation/test split, calibration and threshold selection,
  ablation by feature group, report writing.
- `aidev/detection/content_features.py` (version 3): six new features and the helper code for them.
- `aidev/detection/predict_content.py`: calibrated probability and threshold in the result.
- `tests/`: unit tests.

Libraries used (general-purpose, no phishing-specific code): Python standard library (`html.parser`, `hashlib`, `re`,
`urllib`), pandas, numpy, scikit-learn (`RandomForestClassifier`, `IsotonicRegression`; in the tests also `average_precision_score`
and `roc_auc_score` as an independent cross-check of the hand-written metrics), joblib.

Not used: any copied phishing-detection project, any pretrained phishing model. Datasets by other people (PhreshPhish,
PhiUSIIL, OpenPhish/URLhaus feeds, Tranco) are used as data only.
