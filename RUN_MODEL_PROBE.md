# model_probe — how to run (read-only, changes nothing)

1. Extract this zip INTO your FYP folder (merge). The file lands at  FYP/AIDev/aidev/tools/model_probe.py
2. VS Code terminal:   cd AIDev
3. Activate the SAME Python / venv you use for the backend, then check:
       python -c "import sklearn; print(sklearn.__version__)"        -> must print 1.9.1
4. Run (put the addresses in quotes):
       python -m aidev.tools.model_probe "https://yhdm.one/vod-play/2026872955/hd.html" "https://www.wikipedia.org/"
   - It loads the two model files (the big one takes a while), prints the result, and saves model_probe_output.txt in AIDev.
   - It downloads the page of each address once (same request a normal scan makes). To skip that: add  --no-page
5. Send me model_probe_output.txt. Delete this file and (if you like) model_probe.py afterwards.
