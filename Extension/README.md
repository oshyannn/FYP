# Extension

| Folder | What |
|---|---|
| `chrome/` | The Chrome extension itself. In Chrome: `chrome://extensions` > Developer mode > **Load unpacked** > choose this folder. Details in `chrome/README.md` |
| `ui/` | React/Tailwind source of the popup. `npm install && npm run build` writes into `chrome/popup/` (the build output is committed) |
| `testsite/` | Local test pages for the download guard and navigation checks. `python make_files.py` then `python server.py`, open http://localhost:8000/ |

The extension talks to the Backend at `http://127.0.0.1:5000` (`API_BASE` in `chrome/background.js` and `ui/src/config.ts`; keep both equal).
