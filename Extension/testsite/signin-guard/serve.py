"""Local test pages for the SafeBrowse sign-in guard. Run:   python serve.py     (stop with Ctrl+C)

  http://localhost:8000/   the test pages (open THIS address in Chrome)
  http://127.0.0.1:8001/   a pretend "scammer's server": it only prints what it received, and never stores anything.
                           For a password it prints only the LENGTH, never the text.

localhost and 127.0.0.1 are two different websites to the browser, which is what makes a page on one posting to the other
a "different website" test. Both servers listen on this computer only. Use made-up passwords such as test123, never real ones.
"""
from __future__ import annotations

import http.server
import threading
from pathlib import Path
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
PAGE = b"<!doctype html><meta charset=utf-8><body style='font:16px sans-serif;padding:2rem'><h2>%s</h2><p>%s</p><p><a href='http://localhost:8000/'>Back to the tests</a></p>"


def fields(raw: bytes) -> str:
    out = []
    for k, v in parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items():
        val = v[0]
        out.append(f"{k}=*** ({len(val)} characters)" if "pass" in k.lower() else f"{k}={val[:40]}")
    return ", ".join(out) or "(no fields)"


class Pages(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(HERE), **kw)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        print(f"[site 8000]  POST {self.path}  -> received: {fields(body)}   (a normal, same-site sign-in)", flush=True)
        self._reply(b"Same-site sign-in received", b"This is the normal case: the form was sent to the website you were on.")

    def _reply(self, title: bytes, text: bytes):
        data = PAGE % (title, text)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


class Collector(Pages):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        print(f"[scammer 8001]  POST {self.path}  -> a DIFFERENT website received: {fields(body)}", flush=True)
        self._reply(b"The pretend scammer received your form", b"If you see this, the form WAS sent to the other website (you chose Send anyway, or the guard did not stop it).")

    def do_GET(self):
        print(f"[scammer 8001]  GET {self.path.split('?')[0]}  (OAuth result address, no data)", flush=True)
        self._reply(b"Pretend scammer", b"A GET arrived at the pretend scammer's address.")


def serve(handler, port):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    a, b = serve(Pages, 8000), serve(Collector, 8001)
    print("Test pages: http://localhost:8000/    pretend scammer: http://127.0.0.1:8001/    (Ctrl+C to stop)", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        a.shutdown()
        b.shutdown()
