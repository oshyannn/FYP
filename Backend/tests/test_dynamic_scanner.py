"""Functional, SSRF security, and AI 2 rendered-DOM integration tests for dynamic_scanner."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT.parent / "AIDev"))

from web.services import dynamic_scanner as ds


class SsrfValidationTests(unittest.TestCase):
    def test_blocks_unsupported_schemes(self):
        for bad in ("file:///etc/passwd", "javascript:alert(1)", "data:text/html,hi", "ftp://example.com"):
            ok, _ = ds.validate_public_url(bad)
            self.assertFalse(ok, f"Should reject {bad}")

    def test_normalize_scan_url_defaults_bare_domains_to_https(self):
        self.assertEqual(ds.normalize_scan_url("youtube.com"), ("https://youtube.com", True))
        self.assertEqual(ds.normalize_scan_url("  example.com/path?a=1 "), ("https://example.com/path?a=1", True))
        self.assertEqual(ds.normalize_scan_url("https://youtube.com"), ("https://youtube.com", False))
        self.assertEqual(ds.normalize_scan_url("http://youtube.com"), ("http://youtube.com", False))
        self.assertEqual(ds.normalize_scan_url("javascript:alert(1)"), ("javascript:alert(1)", False))
        ok, err = ds.validate_public_url("example.com", allow_private=True)
        self.assertTrue(ok, err)

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
            self.assertIn("calibrated_percent", res)
            self.assertIn(res.get("risk_tier"), ("flagged", "suspicious", "low"))
            self.assertIn("model_version", res)
            self.assertIn("AI 2 evaluated on browser-rendered DOM", res["note"])

    def test_ai2_threshold_float_tolerance_and_risk_tiers(self):
        html = "<html><body>" + ("login verify account " * 20) + "</body></html>"

        class _DummyModel:
            def __init__(self, prob: float):
                self._p = prob

            def predict_proba(self, _x):
                return [[1.0 - self._p, self._p]]

        class _DummyCal:
            def __init__(self, cal: float):
                self._c = cal

            def predict(self, _x):
                return [self._c]

        from aidev.detection import content_features as cf
        from aidev.detection import predict_content

        sample_feats = cf.extract(html, "https://example.test/login", [], False)
        fnames = list(sample_feats.keys())

        # Exact float-precision case observed on ashy-river-047f25100.8.azurestaticapps.net
        bundle_edge = {
            "version": "test-v3",
            "feature_names": fnames,
            "model": _DummyModel(0.854),
            "calibrator": _DummyCal(0.8235294117647058),
            "threshold": 0.823529411764706,
        }
        with mock.patch.object(predict_content, "_load", return_value=bundle_edge), \
             mock.patch.object(predict_content, "_threshold", return_value=0.823529411764706):
            res = ds._evaluate_ai2_on_rendered_dom(html, "https://example.test/login", [])
        self.assertIsNotNone(res)
        self.assertTrue(res["flagged"])
        self.assertEqual(res["risk_tier"], "flagged")
        self.assertEqual(res["calibrated_percent"], 82.4)

        # Suspicious tier (>= 50% calibrated, below threshold)
        bundle_susp = {**bundle_edge, "model": _DummyModel(0.70), "calibrator": _DummyCal(0.65)}
        with mock.patch.object(predict_content, "_load", return_value=bundle_susp), \
             mock.patch.object(predict_content, "_threshold", return_value=0.8235):
            res_susp = ds._evaluate_ai2_on_rendered_dom(html, "https://example.test/login", [])
        self.assertFalse(res_susp["flagged"])
        self.assertEqual(res_susp["risk_tier"], "suspicious")

        # Low tier (< 50% calibrated)
        bundle_low = {**bundle_edge, "model": _DummyModel(0.20), "calibrator": _DummyCal(0.15)}
        with mock.patch.object(predict_content, "_load", return_value=bundle_low), \
             mock.patch.object(predict_content, "_threshold", return_value=0.8235):
            res_low = ds._evaluate_ai2_on_rendered_dom(html, "https://example.test/login", [])
        self.assertFalse(res_low["flagged"])
        self.assertEqual(res_low["risk_tier"], "low")

    def test_merge_dynamic_ai2_replaces_static_and_recalculates_final_score(self):
        base_analysis = {
            "status": "Safe",
            "risk_score": 16,
            "source": "model+content",
            "ai1": {"name": "AI 1", "state": "ok", "percent": 20, "score": 20, "level": "low", "description": "low"},
            "ai2": {"name": "AI 2", "state": "ok", "percent": 15, "score": 15, "level": "low", "description": "static"},
            "ai_combined": {"name": "AI combined", "state": "ok", "percent": 16, "score": 16, "level": "low", "description": "old"},
            "checks": [{"id": "ai2", "name": "AI 2", "group": "ai", "state": "clear", "detail": "static", "score": 15, "effect": "none"}],
            "final": {
                "status": "Safe", "score": 16,
                "list_api": {"score": None, "text": "none", "trusted": False, "trust_discount": 0},
                "ai": {"score": 16, "text": "old"}, "page_rules_score": 0, "bonus": 0, "notes": [], "method": "", "summary": "",
            },
            "reasons": [],
        }
        ai2_dyn = {
            "probability": 0.90,
            "percent": 90.0,
            "probability_calibrated": 0.85,
            "calibrated_percent": 85.0,
            "threshold": 0.8235,
            "flagged": True,
            "risk_tier": "flagged",
            "signals": ["Password field detected"],
            "categories": [{"id": "fake_login", "label": "Fake login", "percent": 50, "level": "high", "triggered": True}],
        }
        # 30% * 20 + 70% * 85 = 6 + 59.5 = 66; +15 page rules = 81 -> Malicious
        new_level, new_score, updated = ds.merge_dynamic_ai2_into_analysis(base_analysis, ai2_dyn, "safe", 16.0)
        self.assertEqual(updated["ai2"]["source"], "docker_dynamic")
        self.assertEqual(updated["ai2"]["score"], 85)
        self.assertEqual(updated["ai_combined"]["score"], 66)
        self.assertEqual(updated["final"]["page_rules_score"], 15)
        self.assertEqual(new_score, 81.0)
        self.assertEqual(new_level, "malicious")


if __name__ == "__main__":
    unittest.main()
