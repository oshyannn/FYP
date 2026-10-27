# AIDev/models

| File | In git? | Made by |
|---|---|---|
| `model.joblib` (URL model) | no | `python -m aidev.pipeline.train` |
| `model_content.joblib` (page-content model) | no | `python -m aidev.pipeline.train_content` |
| `model_metrics.json`, `model_content_metrics.json` | yes | written by the same commands |
| `backup_20261019/` | metrics + the content model are tracked; the old URL model is not | manual snapshot |
| `backups/` | no | manual snapshots such as `model_content_backup_*.joblib` |

**Version rule:** every model was trained with scikit-learn **1.9.1**. The venvs pin that version in `AIDev/requirements-runtime.txt`.
If you change scikit-learn, retrain first. Models also expect `tldextract` to be installed (see `aidev/core/features.py`).
`predict.py` refuses a model whose feature names or `FEATURE_VERSION` differ.
Side models from `train_content --out NAME` go to `../experiments/`.
