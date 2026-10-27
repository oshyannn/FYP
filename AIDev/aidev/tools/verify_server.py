"""
Local page to check the two models by hand. Run from AIDev/:

    python -m aidev.tools.verify_server          ->  open http://127.0.0.1:8765

Uses predict.py (URL model) and predict_content.py (content model) exactly as detector.py would, so what you see here
is what the system sees. Listens on 127.0.0.1 only. Checking a URL makes the content model download that page
(text only, nothing runs); the site sees your IP address.
"""
from __future__ import annotations

import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from aidev.core import common
from aidev.detection import predict
from aidev.detection import predict_content

PORT = 8765
PAGE = Path(__file__).resolve().with_name("verify.html")


def _num(x):
    try:
        return round(float(x), 4)
    except Exception:
        return None


def _url_model(url: str):
    try:
        r = predict.predict(url)
    except Exception:
        return None
    if not r:
        return None
    return {"probability": _num(r.get("probability")), "model_version": str(r.get("model_version", ""))}


def _content_model(url: str):
    try:
        r = predict_content.predict(url)
    except Exception:
        return None
    if not r:
        return None
    return {"probability": _num(r.get("probability")), "signals": list(r.get("signals", [])),
            "final_url": r.get("final_url"), "latency_ms": r.get("latency_ms"),
            "model_version": str(r.get("model_version", ""))}


def _read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


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
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):           # blocks DNS-rebinding from other websites
            return self._json({"error": "bad host"}, 403)
        u = urlparse(self.path)
        if u.path == "/":
            if not PAGE.exists():
                return self._send(404, b"verify.html not found next to verify_server.py", "text/plain")
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        if u.path == "/api/status":
            c_ok = predict_content.available()
            bundle = getattr(predict_content, "_BUNDLE", None) or {}
            probe = _url_model("https://example.com/")
            return self._json({
                "url_model": {"available": probe is not None, "version": (probe or {}).get("model_version")},
                "content_model": {"available": bool(c_ok), "version": bundle.get("version"),
                                  "n_features": len(bundle.get("feature_names", [])),
                                  "eval_mode": bundle.get("eval_mode")}})
        if u.path == "/api/metrics":
            return self._json({"url": _read_json(common.METRICS_PATH), "content": _read_json(common.CONTENT_METRICS_PATH)})
        if u.path == "/api/check":
            url = (parse_qs(u.query).get("url") or [""])[0].strip()
            if not url.lower().startswith(("http://", "https://")):
                return self._json({"error": "URL must start with http:// or https://"}, 400)
            return self._json({"url": url, "url_model": _url_model(url), "content_model": _content_model(url)})
        self._json({"error": "not found"}, 404)

    def log_message(self, *a) -> None:
        pass


if __name__ == "__main__":
    print(f"open http://127.0.0.1:{PORT}   (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
