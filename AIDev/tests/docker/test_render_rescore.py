import os
import unittest
from unittest import mock

from aidev.detection.docker import render_rescore as rr


class FakeModel:
    def predict_proba(self, x):
        return [[0.2, 0.8]]


class FakeCal:
    def predict(self, x):
        return [0.9]


BUNDLE = {"render_band": (0.2, 0.8), "model": FakeModel(), "calibrator": FakeCal(),
          "threshold": 0.5, "feature_names": ["a"], "feature_version": 1}
STATIC = {"probability_calibrated": 0.5}
OK_RENDER = {"ok": True, "html": "<html>x</html>", "final_url": "http://x/", "redirects": [], "status": 200}


class TestRenderRescore(unittest.TestCase):
    def test_off_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RENDER_CHECK", None)
            with mock.patch.object(rr, "_run_container") as run:
                out = rr.rescore("http://x/", STATIC)
        self.assertFalse(out["render_used"])
        run.assert_not_called()

    def test_outside_band_no_render(self):
        with mock.patch.dict(os.environ, {"RENDER_CHECK": "1"}), \
             mock.patch.object(rr, "_load", return_value=BUNDLE), \
             mock.patch.object(rr, "_run_container") as run:
            out = rr.rescore("http://x/", {"probability_calibrated": 0.99})
        self.assertEqual(out["render_status"], "outside_band")
        run.assert_not_called()

    def test_inside_band_success(self):
        with mock.patch.dict(os.environ, {"RENDER_CHECK": "1"}), \
             mock.patch.object(rr, "_load", return_value=BUNDLE), \
             mock.patch.object(rr, "_run_container", return_value=OK_RENDER), \
             mock.patch.object(rr.cf, "extract", return_value={"a": 1.0}):
            out = rr.rescore("http://x/", STATIC)
        self.assertTrue(out["render_used"])
        self.assertEqual(out["render_status"], "ok")
        self.assertTrue(out["flagged_rendered"])

    def test_render_failed_keeps_static(self):
        bad = {"ok": False, "html": "", "status": 404, "error": ""}
        with mock.patch.dict(os.environ, {"RENDER_CHECK": "1"}), \
             mock.patch.object(rr, "_load", return_value=BUNDLE), \
             mock.patch.object(rr, "_run_container", return_value=bad):
            out = rr.rescore("http://x/", STATIC)
        self.assertFalse(out["render_used"])
        self.assertTrue(out["render_status"].startswith("render_failed"))

    def test_never_raises(self):
        with mock.patch.dict(os.environ, {"RENDER_CHECK": "1"}), \
             mock.patch.object(rr, "_load", return_value=BUNDLE), \
             mock.patch.object(rr, "_run_container", side_effect=RuntimeError("boom")):
            out = rr.rescore("http://x/", STATIC)
        self.assertEqual(out["render_status"], "error")
        self.assertFalse(out["render_used"])


if __name__ == "__main__":
    unittest.main()