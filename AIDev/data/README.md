# AIDev/data (NOT in git)

Everything here is downloaded or generated, so git ignores it (only this file and `.gitkeep` are tracked). On a new machine, rebuild it with
the commands below, run from the `AIDev/` folder with its venv active. Some files are private or too big for GitHub.

| File / folder | Made by | Notes |
|---|---|---|
| `tranco_top.txt`, `feeds_urls.txt` | `python -m aidev.pipeline.feeds` | Tranco top list; OpenPhish + URLhaus. Re-run about daily. Used by the live detector too |
| `phishing_extra.csv` | `python -m aidev.pipeline.import_phishtank` | needs `PHISHTANK_API_KEY` in `AIDev/.env` |
| `benign_extra.csv` | `python -m aidev.pipeline.export_history` | **private**: your own Chrome history. Never share or commit |
| `phishing_labeled.csv`, `benign_labeled.csv` | `python -m aidev.pipeline.import_labeled raw/PhiUSIIL_Phishing_URL_Dataset.csv --url-col URL --label-col label --benign-value 1` | from the PhiUSIIL dataset (UCI #967) |
| `raw/PhiUSIIL_Phishing_URL_Dataset.csv` | download from UCI | original dataset file, ~54 MB |
| `adult_domains.txt` | `python -m aidev.pipeline.import_adult` | ~1M domains; used by the live detector |
| `dataset.csv` | `python -m aidev.pipeline.build_dataset` | training table (url, label, group) |
| `rdap_dns.json` | created automatically by `aidev/detection/rdap.py` | cache, safe to delete |
| `pages/pages.csv`, `pages/html/*.html.gz` | `python -m aidev.pipeline.crawl_pages` or `python -m aidev.pipeline.import_phreshphish --n 6000` | page HTML for the content model, ~450 MB |

Order for a full rebuild: `feeds` -> (`import_phishtank`) -> (`export_history`) -> (`import_labeled`) -> `build_dataset` -> `train`;
content model: `import_phreshphish` or `crawl_pages` -> `train_content`.
