"""Teacher demo for model 2 (page content). Local only, no extra packages.

    cd AIDev
    python -m aidev.samples.ai2.make_samples     (once, creates the demo pages)
    python -m aidev.samples.ai2.app
    open http://127.0.0.1:8765

The app never fetches a URL and never runs page code. It only scores the HTML in the box or a demo file.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from aidev.samples.ai2.score_html import model_status, score_html

HERE = Path(__file__).resolve().parent
PAGES = HERE / "pages"
MANIFEST = HERE / "manifest.json"
PORT = 8765
MAX_BODY = 2_000_000


def load_manifest() -> list:
    if not MANIFEST.exists():
        return []
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Model 2 demo: page content</title>
<style>
body{font-family:system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;color:#1d1d1f}
h1{font-size:22px} h3{margin-top:22px;font-size:16px}
textarea{width:100%;height:170px;font-family:monospace;font-size:12px;box-sizing:border-box}
input[type=text]{width:100%;padding:6px;box-sizing:border-box}
button{padding:8px 16px;margin-top:8px;cursor:pointer}
.box{border:1px solid #ddd;border-radius:8px;padding:14px;margin-top:14px}
.flag{color:#b00020;font-weight:600;font-size:16px} .ok{color:#1b7f3b;font-weight:600;font-size:16px}
.muted{color:#666;font-size:13px} table{border-collapse:collapse;width:100%;margin-top:8px}
td,th{border-bottom:1px solid #eee;padding:6px;text-align:left;font-size:14px}
</style></head><body>
<h1>Model 2: scoring a page from its HTML</h1>
<p class="muted">This demo does not open any website and does not run any page code. It only reads the HTML in the box.
The demo pages are fictional (ExampleBank, .test domains).</p>
<div id="status" class="muted"></div>

<h3>1. Choose a demo page</h3>
<select id="samples"></select> <button id="load">Load demo page</button>

<h3>2. Or paste HTML</h3>
<label class="muted">URL of the page (used for link checks)</label>
<input type="text" id="url" value="https://example.test/">
<textarea id="html" placeholder="Paste the HTML source here"></textarea>
<br><button id="run">Score this page</button>

<div id="result"></div>

<script>
const $ = id => document.getElementById(id);
let current = null;

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  e.textContent = text;
  return e;
}

async function init() {
  const st = await (await fetch("/api/status")).json();
  $("status").textContent = st.loaded
    ? "Model loaded (version " + (st.version || "?") + ")"
    : "Model NOT loaded: " + st.reason;
  const list = await (await fetch("/api/samples")).json();
  if (!list.length) {
    $("samples").appendChild(el("option", "(no demo pages: run make_samples first)"));
  }
  for (const s of list) {
    const o = el("option", s.title);
    o.value = JSON.stringify(s);
    $("samples").appendChild(o);
  }
}

$("load").onclick = async () => {
  if (!$("samples").value) return;
  const s = JSON.parse($("samples").value);
  const txt = await (await fetch("/api/sample?name=" + encodeURIComponent(s.file))).text();
  $("html").value = txt;
  $("url").value = s.url;
  current = s;
  $("result").innerHTML = "";
};

$("run").onclick = async () => {
  const html = $("html").value;
  $("result").innerHTML = "";
  if (!html.trim()) {
    $("result").appendChild(el("p", "Paste some HTML or load a demo page first.", "muted"));
    return;
  }
  const r = await fetch("/api/score", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({html: html, url: $("url").value})
  });
  const res = await r.json();
  const box = el("div", "", "box");
  $("result").appendChild(box);
  if (!r.ok || res.error) {
    box.appendChild(el("p", "Error: " + (res.error || r.status), "flag"));
    return;
  }
  if (res.flagged === true) {
    box.appendChild(el("p", "Flagged: possible phishing (calibrated score above the threshold)", "flag"));
  } else if (res.flagged === false) {
    box.appendChild(el("p", "Not flagged (calibrated score below the threshold)", "ok"));
  } else {
    box.appendChild(el("p", "No decision (page too short, or model/threshold missing)", "muted"));
  }
  if (res.note) box.appendChild(el("p", res.note, "muted"));

  const t = document.createElement("table");
  const rows = [
    ["Raw forest probability", res.probability],
    ["Calibrated probability (0.8 = about 80% of similar pages were phishing)", res.probability_calibrated],
    ["Threshold (1% of benign validation pages flagged)", res.threshold]
  ];
  for (const [k, v] of rows) {
    const tr = document.createElement("tr");
    tr.appendChild(el("td", k));
    tr.appendChild(el("td", v === null || v === undefined ? "-" : String(v)));
    t.appendChild(tr);
  }
  box.appendChild(t);

  if (res.signals && res.signals.length) {
    box.appendChild(el("p", "Reasons found in the page:"));
    const ul = document.createElement("ul");
    for (const s of res.signals) ul.appendChild(el("li", s));
    box.appendChild(ul);
  } else {
    box.appendChild(el("p", "No suspicious reasons found by the rules.", "muted"));
  }

  if (current && current.url === $("url").value) {
    box.appendChild(el("p", "Expected for this demo page: " + current.expected + ". " + current.why, "muted"));
    box.appendChild(el("p", current.note, "muted"));
  }
};

init();
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/":
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif url.path == "/api/status":
            self._send(200, json.dumps(model_status()).encode("utf-8"), "application/json")
        elif url.path == "/api/samples":
            self._send(200, json.dumps(load_manifest(), ensure_ascii=False).encode("utf-8"), "application/json")
        elif url.path == "/api/sample":
            name = parse_qs(url.query).get("name", [""])[0]
            allowed = {s["file"] for s in load_manifest()}
            if name not in allowed:                          # only files listed in the manifest
                self._send(404, b"not found", "text/plain")
                return
            self._send(200, (PAGES / name).read_bytes(), "text/plain; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if urlsplit(self.path).path != "/api/score":
            self._send(404, b"not found", "text/plain")
            return
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > MAX_BODY:
            self._send(413, b'{"error": "too large"}', "application/json")
            return
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
            html = str(data.get("html", ""))
            page_url = str(data.get("url", "") or "https://example.test/")
            res = score_html(html, page_url)
            self._send(200, json.dumps(res, ensure_ascii=False).encode("utf-8"), "application/json")
        except Exception as exc:
            self._send(500, json.dumps({"error": f"{type(exc).__name__}: {exc}"}).encode("utf-8"), "application/json")

    def log_message(self, fmt, *args):                        # keep the console quiet
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Open http://127.0.0.1:{PORT} in a browser (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
