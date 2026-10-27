# AIDev: detection engine + data + training

Python package `aidev` (in `aidev/`) plus the files it works on:

| Path | What |
|---|---|
| `aidev/core/` | paths (`common.py`) and the 29 URL features (`features.py`) |
| `aidev/detection/` | `detector.analyze(url)` and everything it combines: URL model, content model, look-alike, PhishTank, Safe Browsing, RDAP |
| `aidev/pipeline/` | download data, build the dataset, train both models |
| `aidev/evaluation/` | evaluation scripts, `check_sources` (explain a verdict) |
| `aidev/tools/` | manual test helpers, model status page (`verify_server`) |
| `lists/` | hand-edited whitelist / blacklist / protected domains (in git) |
| `data/`, `models/`, `experiments/` | big or private files, not in git (see the README in `data/` and `models/`) |
| `docs/ML_HANDOFF.md` | data, features, metrics, detector rules, known weaknesses |

Backend imports this package (`Backend/app.py` adds `AIDev/` to `sys.path`).

## Use
Run from this folder with its venv active (`..\setup_envs.py` creates it):
```
.venv\Scripts\activate
python -m aidev.tools.try_urls https://example.com/        # score with the URL model
python -m aidev.tools.testai https://example.com/          # every detector layer with reasons
python -m aidev.pipeline.feeds                             # refresh data (see data/README.md for the full order)
python -m aidev.pipeline.train
python -m aidev.tools.verify_server                        # model status page on http://127.0.0.1:8765
```
Keys go in `AIDev/.env` (copy `.env.example`).
