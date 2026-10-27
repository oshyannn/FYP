# FYP: Real-Time Malicious URL Detection System (SafeBrowse)

Final-year project (BMCS3403). A Chrome extension and a desktop app check the websites you visit; a Python backend decides whether a URL is
safe, suspicious, malicious or restricted, using lists, PhishTank, Google Safe Browsing, look-alike detection, domain age and two Random Forest models.

**Full file map (written for AI assistants too): [`file_structure.md`](file_structure.md).**

| Folder | What | Language | Own environment |
|---|---|---|---|
| [`DesktopApp/`](DesktopApp) | Desktop app (Electron + React + Vite): sign-up, login, pairing code for the extension | TypeScript | `node_modules` |
| [`AIDev/`](AIDev) | Detection engine, data, models, training pipeline | Python | `AIDev/.venv` |
| [`Backend/`](Backend) | Flask API (`/analyze`, accounts, database); uses the engine from `AIDev/` | Python | `Backend/.venv` |
| [`Extension/`](Extension) | `chrome/` the extension, `ui/` React popup source, `testsite/` test pages | JavaScript | `Extension/ui/node_modules` |

## First-time setup
```
python setup_envs.py          # creates AIDev/.venv and Backend/.venv, installs packages, runs npm install
```
Then copy `AIDev/.env.example` to `AIDev/.env` and `Backend/.env.example` to `Backend/.env` and fill them in.
The big files (`AIDev/data/`, `AIDev/models/*.joblib`) are not in git: see the README in those folders for how to rebuild them.

## Run
```
cd Backend  && .venv\Scripts\activate && python app.py        # API on http://127.0.0.1:5000
cd DesktopApp && npm run dev                                   # desktop app
```
Extension: Chrome > `chrome://extensions` > Developer mode > Load unpacked > `Extension/chrome`.
