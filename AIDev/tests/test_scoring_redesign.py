"""Unit tests for the redesigned weighted scoring system (30% AI 1 / 70% AI 2 + Reputation/Rules)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aidev.detection import detector


class ScoringHelpersTests(unittest.TestCase):
    def test_direct_probability_mapping_and_ai1_cap(self):
        self.assertEqual(detector._ml_to_score(0.25), 25)
        self.assertEqual(detector._ml_to_score(0.95), 75)  # AI 1 capped at 75 alone
        self.assertEqual(detector._content_to_score(0.82), 82)

    def test_ai_combined_30_70_weights_and_agreement_bonus(self):
        # 0.30 * 20 + 0.70 * 80 = 6 + 56 = 62 (no agreement bonus since AI 1 < 50)
        res = detector._ai_combined(20, 80)
        self.assertEqual(res["score"], 62)
        self.assertEqual(res["level"], "elevated")

        # Both >= 50: 0.30 * 60 + 0.70 * 80 = 74 + 10 = 84
        res_both = detector._ai_combined(60, 80)
        self.assertEqual(res_both["score"], 84)
        self.assertEqual(res_both["level"], "high")


class WeightedAnalyzeTests(unittest.TestCase):
    def _mock_clean_env(self, *, pt=None, sb=None, la=None, age=None, ml=None, content=None):
        pt = pt or SimpleNamespace(succeeded=True, risk_contribution=None, found=False, match_scope=None, phish_id=None, matched_url=None, detail_url=None)
        sb = sb or SimpleNamespace(configured=True, succeeded=True, risk_contribution=None, threat_type=None)
        rdap_res = SimpleNamespace(succeeded=age is not None, age_days=age, registrant=None)
        return (
            mock.patch.object(detector, "_phishtank", return_value=pt),
            mock.patch.object(detector, "_safebrowsing", return_value=sb),
            mock.patch.object(detector.lookalike, "check", return_value=la),
            mock.patch.object(detector.rdap, "lookup", return_value=rdap_res),
            mock.patch.object(detector, "ml_predict", return_value=ml),
            mock.patch.object(detector.predict_content, "enabled", return_value=True),
            mock.patch.object(detector.predict_content, "predict", return_value=content),
            mock.patch.object(detector, "is_shared", return_value=False),
            mock.patch.object(detector, "_admin_hit", return_value=None),
        )

    def test_clean_ai_on_unknown_domain_returns_safe_with_score(self):
        patches = self._mock_clean_env(
            ml={"probability": 0.10},
            content={"probability": 0.10, "signals": [], "features": None},
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8]:
            res = detector.analyze("https://clean-unknown-site-12345.test/", use_ai=True)
        self.assertEqual(res["status"], "Safe")
        self.assertEqual(res["risk_score"], 10)
        self.assertTrue(res["has_data"])

    def test_ai_and_new_domain_combine_with_agreement_bonus(self):
        # AI1=20, AI2=80 -> ai_comb=62; age=10d -> rep=40; 0.55*62 + 0.45*40 + 15 = 34.1 + 18 + 15 = 67
        patches = self._mock_clean_env(
            age=10,
            ml={"probability": 0.20},
            content={"probability": 0.80, "signals": ["login form"], "features": None},
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8]:
            res = detector.analyze("https://fresh-login-site-12345.test/", use_ai=True)
        self.assertEqual(res["status"], "Suspicious")
        self.assertEqual(res["risk_score"], 67)

    def test_whitelist_with_use_ai_applies_trust_discount_not_blindfold(self):
        with mock.patch.object(detector, "WHITELIST", {"trusted-example.com"}):
            # Fast path (use_ai=False) stays instant Safe 5
            fast = detector.analyze("https://trusted-example.com/", use_ai=False)
            self.assertEqual(fast["status"], "Safe")
            self.assertEqual(fast["risk_score"], 5)

            # With use_ai=True and extreme AI risk (75 and 95 -> ai_comb=99), -25 trust = 74 -> Malicious!
            patches = self._mock_clean_env(
                ml={"probability": 0.90},
                content={"probability": 0.95, "signals": ["phishing"], "features": None},
            )
            with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8]:
                compromised = detector.analyze("https://trusted-example.com/phish", use_ai=True)
            self.assertEqual(compromised["status"], "Malicious")
            self.assertGreaterEqual(compromised["risk_score"], 70)

    def test_confirmed_safebrowsing_keeps_malicious_floor(self):
        sb = SimpleNamespace(configured=True, succeeded=True, risk_contribution=90, threat_type="SOCIAL_ENGINEERING")
        patches = self._mock_clean_env(
            sb=sb,
            ml={"probability": 0.05},
            content={"probability": 0.05, "signals": [], "features": None},
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8]:
            res = detector.analyze("https://confirmed-evil-12345.test/", use_ai=True)
        self.assertEqual(res["status"], "Malicious")
        self.assertGreaterEqual(res["risk_score"], 90)


if __name__ == "__main__":
    unittest.main()
