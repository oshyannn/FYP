"""
Local test site for the CONTENT model. Run from AIDev/ (uses aidev/tools/test_samples.py):

    python -m aidev.tools.content_testsite        ->  open http://127.0.0.1:8001/

Shows 8 sample pages. "Open page" lets you see the page like a user would; "Score with model" runs the live content
model on that page's HTML. Each page is scored as if it came from a made-up public address (shown on the card),
because pagefetch.py deliberately refuses localhost, so the model cannot download these pages itself.
All pages are inert mock-ups: text only, forms point at addresses that cannot resolve, nothing is stored.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from aidev.detection import content_features as cf
from aidev.detection import predict_content as pc
from aidev.tools.test_samples import SAMPLES

PORT = 8001
STYLE = ("<style>body{font-family:system-ui;max-width:720px;margin:30px auto;padding:0 16px;line-height:1.5}"
         "ul{display:flex;flex-wrap:wrap;gap:8px 14px;padding:0;list-style:none;font-size:13px}"
         "input{display:block;margin:6px 0;padding:6px;width:100%;max-width:320px}"
         "button,input[type=submit]{padding:8px 14px}footer{margin-top:30px;color:#777;font-size:13px}</style>")
NOTES = [
    "Ordinary news page: lots of text and links. Expected: low score.",
    "Documentation page. Expected: low score.",
    "Genuine-style login: has a password box, but the form posts to its own site. Expected: low to middling. Login pages are the model's known weak spot.",
    "Imitates a brand login: password goes to another website, hidden frame, scrambled script, right-click blocked. Expected: high.",
    "Asks for card number, CVV and OTP; the form goes nowhere. Expected: raised.",
    "Fake 'update required' page pushing a program download. Expected: raised.",
    "Almost empty page that only sends you elsewhere (opening it bounces to an address that does not exist). Expected: raised.",
    "Page built by JavaScript: the HTML itself is almost empty. Expected: no opinion.",
]
JS_ONLY = ('<html><head><title>Loading</title></head><body><div id="app"></div>'
           '<script src="/bundle.js"></script></body></html>')

PAGES = []
for i, (name, url, kind, html) in enumerate(SAMPLES):
    PAGES.append({"id": i, "name": name.split(": ", 1)[-1], "kind": kind, "url": url, "note": NOTES[i],
                  "html": html.replace("</head>", STYLE + "</head>", 1) if "</head>" in html else html})
PAGES.append({"id": len(PAGES), "name": "JavaScript-only page", "kind": "unknown", "url": "https://app.spa-site.example/",
              "note": NOTES[-1], "html": JS_ONLY})


def score(p: dict) -> dict:
    b = pc._load()
    if b is None:
        return {"error": "content model not loaded (model_content.joblib missing or content_features.py is not version 2)"}
    if len(p["html"]) < 200:
        return {"probability": None, "note": "no opinion: the page is too small / built by JavaScript, so there is nothing to read"}
    f = cf.extract(p["html"], p["url"])
    prob = float(b["model"].predict_proba([[f[n] for n in b["feature_names"]]])[0][1])
    return {"probability": round(prob, 4), "signals": pc.signals(f), "model_version": b.get("version")}


INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Content model test site</title><style>
:root{--bg:#fff;--fg:#1b1b1f;--mut:#667;--card:#f5f6f8;--line:#d8dbe0;--acc:#2457d6;--bad:#c62828;--ok:#2e7d32;--warn:#b26a00;color-scheme:light dark}
@media(prefers-color-scheme:dark){:root{--bg:#15161a;--fg:#e8e8ec;--mut:#9aa0ac;--card:#1e2026;--line:#33363f;--acc:#7aa2ff;--bad:#ff6b6b;--ok:#6fcf7a;--warn:#f0b04a}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}main{max-width:820px;margin:0 auto;padding:20px 16px 60px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;margin:10px 0}.mut{color:var(--mut);font-size:13px}
a.btn,button{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 12px;cursor:pointer;text-decoration:none;display:inline-block}
button.go{background:var(--acc);color:#fff;border-color:var(--acc)}.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin:6px 0}.bar i{display:block;height:100%}
.big{font-size:22px;font-weight:600}.bad{color:var(--bad)}.warn{color:var(--warn)}.ok{color:var(--ok)}h1{font-size:20px;margin:0 0 4px}
</style></head><body><main><h1>Content model test site</h1>
<div class="mut" id="st">Each card is a sample page. Open it to see what a visitor sees; score it to see what the model thinks. Pages are scored as if they came from the address shown, not from localhost.</div>
<p><button class="go" id="all">Score all</button></p><div id="list"></div>
<div class="mut">Verdict bands follow the detector: 70% and above = Suspicious, 40-70% = slightly risky, below = no strong signal (not a guarantee of safety). These are hand-made pages, so this tests that the function works, not how accurate it is.</div>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function show(id,r){const el=document.getElementById('r'+id);if(r.error){el.innerHTML=`<div class="bad">${esc(r.error)}</div>`;return}
 if(r.probability==null){el.innerHTML=`<div class="mut"><b>No opinion.</b> ${esc(r.note)}</div>`;return}
 const p=r.probability,c=p>=.7?'bad':p>=.4?'warn':'ok',v=p>=.7?'Suspicious':p>=.4?'Slightly risky':'No strong signal';
 el.innerHTML=`<div class="big ${c}">${(100*p).toFixed(1)}% <span style="font-size:15px">${v}</span></div><div class="bar"><i class="${c}" style="width:${100*p}%;background:currentColor"></i></div>`+
 (r.signals.length?'<ul>'+r.signals.map(s=>`<li>${esc(s)}</li>`).join('')+'</ul>':'<div class="mut">No individual warning signs found in the page.</div>')}
async function score(id){const el=document.getElementById('r'+id);el.innerHTML='<div class="mut">scoring...</div>';
 try{show(id,await (await fetch('/api/score?id='+id)).json())}catch(e){el.innerHTML='<div class="bad">server not reachable</div>'}}
fetch('/api/pages').then(r=>r.json()).then(L=>{document.getElementById('list').innerHTML=L.map(p=>`<div class="card"><b>${p.id+1}. ${esc(p.name)}</b>
 <span class="mut">(${p.kind})</span><div class="mut">${esc(p.note)}</div><div class="mut">scored as: ${esc(p.url)}</div>
 <p><a class="btn" target="_blank" href="/page/${p.id}">Open page</a> <button class="go" onclick="score(${p.id})">Score with model</button></p><div id="r${p.id}"></div></div>`).join('');
 document.getElementById('all').onclick=async()=>{for(const p of L)await score(p.id)}});
</script></main></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self) -> None:
        if (self.headers.get("Host") or "").split(":")[0] not in ("127.0.0.1", "localhost"):
            return self._json({"error": "bad host"}, 403)
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(200, INDEX.encode("utf-8"), "text/html; charset=utf-8")
        if u.path == "/api/pages":
            return self._json([{k: p[k] for k in ("id", "name", "kind", "url", "note")} for p in PAGES])
        if u.path.startswith("/page/") and u.path[6:].isdigit() and int(u.path[6:]) < len(PAGES):
            return self._send(200, PAGES[int(u.path[6:])]["html"].encode("utf-8"), "text/html; charset=utf-8")
        if u.path == "/api/score":
            i = (parse_qs(u.query).get("id") or [""])[0]
            if i.isdigit() and int(i) < len(PAGES):
                return self._json(score(PAGES[int(i)]))
            return self._json({"error": "unknown page"}, 404)
        self._send(404, b"not found", "text/plain")

    def log_message(self, *a) -> None:
        pass


if __name__ == "__main__":
    print(f"open http://127.0.0.1:{PORT}   (Ctrl+C to stop)")
    try:
        ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
    except KeyboardInterrupt:
        print("stopped")
