"""Functional, SSRF security, and AI 2 rendered-DOM integration tests for dynamic_scanner."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "AIDev"))

from web.services import dynamic_scanner as ds


class SsrfValidationTests(unittest.TestCase):
    def test_blocks_unsupported_schemes(self):
        for bad in ("file:///etc/passwd", "javascript:alert(1)", "data:text/html,hi", "ftp://example.com"):
            ok, _ = ds.validate_public_url(bad)
            self.assertFalse(ok, f"Should reject {bad}")

    def test_blocks_loopback_private_and_metadata_ips(self):
        for bad in (
            "http://127.0.0.1/",
            "http://localhost:5000/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://[fe80::1]/",
        ):
            ok, _ = ds.validate_public_url(bad)
            self.assertFalse(ok, f"Should block {bad}")


class EvidenceAndAi2Tests(unittest.TestCase):
    def test_normalize_strips_rendered_html_and_caps_fields(self):
        raw = {
            "schema_version": 1,
            "requested_url": "https://example.com/",
            "final_url": "https://example.com/login",
            "navigation": {"redirect_count": 1, "redirect_urls": ["https://example.com/", "https://example.com/login"], "http_status": 200},
            "network": {"request_count": 5, "external_domains": ["cdn.example.net"], "failed_request_count": 0, "blocked_ssrf_count": 0},
            "scripts": {"external_script_count": 1, "inline_script_count": 2, "script_urls": ["https://cdn.example.net/app.js"]},
            "dom": {"snapshot_captured": True, "rendered_html": "<html><body>hi</body></html>", "form_count": 1, "password_field_count": 1, "iframe_count": 0, "external_form_actions": ["evil.example"]},
            "behaviour": {"popup_count": 0, "download_attempt_count": 0, "download_filenames": [], "console_error_count": 0, "page_error_count": 0},
            "limitations": ["Window limited"],
        }
        ev, html, redirects = ds._normalize_evidence(raw)
        self.assertEqual(html, "<html><body>hi</body></html>")
        self.assertEqual(len(redirects), 2)
        self.assertNotIn("rendered_html", ev["dom"])
        self.assertTrue(ev["dom"]["snapshot_captured"])
        self.assertEqual(ev["dom"]["rendered_html_bytes"], len(html.encode("utf-8")))

    def test_ai2_evaluates_rendered_dom_contract(self):
        html = (
            "<!doctype html><html lang='en'><head><title>PayPal Security Verification</title></head>"
            "<body><h1>Verify your PayPal account</h1>"
            "<form action='https://198.51.100.10/collect' method='post'>"
            "<input type='email' name='email'><input type='password' name='password'>"
            "<button type='submit'>Confirm</button></form></body></html>"
        )
        res = ds._evaluate_ai2_on_rendered_dom(html, "https://phish.example.test/login", ["https://phish.example.test/"])
        if res is not None:  # None only when model_content.joblib is absent
            self.assertIn("probability", res)
            self.assertIn("percent", res)
            self.assertIn("model_version", res)
            self.assertIn("AI 2 evaluated on browser-rendered DOM", res["note"])


if __name__ == "__main__":
    unittest.main()
