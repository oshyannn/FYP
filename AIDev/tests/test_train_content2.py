"""Tests for pipeline_own2/train_content2.py and the calibrated output of detection/predict_content.py.  Run from AIDev/:
    python -m unittest tests.test_train_content2 -v"""
import gzip
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.isotonic import IsotonicRegression

from aidev.detection import content_features as cf
from aidev.evaluation import eval_content_own as ev
from aidev.pipeline_own2 import train_content2 as t2


def _df(n=1200, seed=0):
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.4).astype(int)
    d = pd.DataFrame({"label": y, "cluster": rng.integers(0, 400, n),
                      "source": np.where(y == 1, "phish_feed", np.where(rng.random(n) < 0.5, "benign_top", "phreshphish_benign"))})
    for i, name in enumerate(cf.FEATURE_NAMES[:3]):
        d[name] = rng.normal(y * (1.0 - 0.3 * i), 1.0)
    d["group"] = d.cluster
    return d


class GroupTests(unittest.TestCase):
    def test_every_feature_in_exactly_one_group(self):
        flat = [n for g in t2.FEATURE_GROUPS.values() for n in g]
        self.assertEqual(sorted(flat), sorted(cf.FEATURE_NAMES))
        self.assertEqual(len(flat), len(set(flat)))

    def test_v3_names_exist(self):
        self.assertTrue(set(t2.V3_FEATURES) <= set(cf.FEATURE_NAMES))
        self.assertTrue(set(t2.SIZE_FEATURES) <= set(cf.FEATURE_NAMES))


class SplitTests(unittest.TestCase):
    def test_clusters_never_straddle(self):
        d = _df()
        tr, va, te = t2.split(d, "", seed=1)
        self.assertFalse((tr & va).any() or (tr & te).any() or (va & te).any())
        self.assertTrue((tr | va | te).all())
        for a, b in ((tr, va), (tr, te), (va, te)):
            self.assertFalse(set(d.cluster[a]) & set(d.cluster[b]))

    def test_own_mode_tests_only_own_pages_and_removes_whole_test_clusters(self):
        d = _df()
        tr, va, te = t2.split(d, "own", seed=1)
        self.assertFalse(d.source[te].str.startswith("phreshphish_").any())
        self.assertFalse(set(d.cluster[te]) & set(d.cluster[tr]))
        self.assertFalse(set(d.cluster[te]) & set(d.cluster[va]))

    def test_deterministic(self):
        d = _df()
        a = t2.split(d, "", seed=5)
        b = t2.split(d, "", seed=5)
        self.assertTrue(all((x == y).all() for x, y in zip(a, b)))


class CalibrationTests(unittest.TestCase):
    def test_threshold_keeps_validation_fpr_within_budget_and_calibrator_is_monotone(self):
        d = _df(3000)
        names = cf.FEATURE_NAMES[:3]
        tr, va, te = t2.split(d, "", seed=2)
        model, cal, thr, cap_report, op = t2.fit_calibrated(d, names, tr, va, cap=0, seed=2)
        v = d[va]
        p = cal.predict(model.predict_proba(v[names])[:, 1])
        self.assertTrue(((p >= 0) & (p <= 1)).all())
        flagged_benign = (p[v.label.to_numpy() == 0] >= thr).mean()
        self.assertLessEqual(flagged_benign, t2.FPR_TARGET + 1e-9)
        grid = np.linspace(0, 1, 50)
        self.assertTrue((np.diff(cal.predict(grid)) >= -1e-12).all())

    def test_ablation_runs_and_skips_absent_groups(self):
        d = _df(1500)
        names = cf.FEATURE_NAMES[:3]                      # only "forms" and "links_resources"/"brand_title" members present
        tr, va, te = t2.split(d, "", seed=3)
        rows = t2.ablation(d, names, tr, va, te, cap=0, seed=3, n_boot=30)
        self.assertEqual(rows[0]["removed"], "(none, all features)")
        self.assertTrue(all(r["n_features"] >= 1 for r in rows))
        self.assertNotIn("redirects_tls", [r["removed"] for r in rows])


class CacheTests(unittest.TestCase):
    def _pages(self, d: Path):
        (d / "html").mkdir()
        rows = ["url,label,source,group,final_url,status,tls_invalid,redirects,html_file,fetched_at"]
        for i in range(3):
            with gzip.open(d / "html" / f"{i}.html.gz", "wt") as f:
                f.write(f"<html><title>t{i}</title><form action='x'><input name=a></form></html>")
            rows.append(f"http://a{i}.com/,{i % 2},benign_top,a{i}.com,http://a{i}.com/,200,0,,{i}.html.gz,2026-01-01")
        (d / "pages.csv").write_text("\n".join(rows), encoding="utf-8")

    def test_second_load_uses_cache_and_change_invalidates_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self._pages(d)
            first = t2.load(d)
            self.assertTrue((d / "features_cache.joblib").exists())
            with mock.patch.object(t2, "_extract_all", side_effect=AssertionError("cache not used")):
                again = t2.load(d)
            pd.testing.assert_frame_equal(first, again)
            with mock.patch.object(t2, "_extract_all", return_value=first.iloc[:1]) as m:
                t2.load(d, rebuild=True)                       # forced rebuild
                self.assertEqual(m.call_count, 1)
                t2.load(d, use_cache=False)                     # cache switched off
                self.assertEqual(m.call_count, 2)
            (d / "pages.csv").write_text((d / "pages.csv").read_text() + "\n", encoding="utf-8")   # pages.csv changed
            with mock.patch.object(t2, "_extract_all", return_value=first.iloc[:2]) as m:
                self.assertEqual(len(t2.load(d)), 2)
                self.assertEqual(m.call_count, 1)


class PredictContentTests(unittest.TestCase):
    """predict() with a fake page: the old keys are unchanged, the new keys appear."""

    def _bundle(self, with_cal=True):
        rng = np.random.default_rng(0)
        names = cf.FEATURE_NAMES[:3]
        X = rng.normal(size=(300, 3))
        y = (X[:, 0] > 0).astype(int)
        rf = RandomForestClassifier(n_estimators=20, random_state=0).fit(pd.DataFrame(X, columns=names), y)
        b = {"model": rf, "feature_names": names, "feature_version": cf.CONTENT_FEATURE_VERSION, "version": "t"}
        if with_cal:
            raw = rf.predict_proba(pd.DataFrame(X, columns=names))[:, 1]
            b["calibrator"] = IsotonicRegression(out_of_bounds="clip").fit(raw, y)
            b["threshold"] = 0.5
        return b

    def _run(self, bundle, setting=None):
        import aidev.core as core_pkg
        from aidev.detection import predict_content as pc
        page = types.SimpleNamespace(ok=True, html="<html><title>x</title>" + "<p>text</p>" * 40 + "</html>", url="https://a.example.com/",
                                     redirects=[], tls_invalid=False, download=None, error=None)
        fake_ls = types.SimpleNamespace(setting=(lambda k, d=None: setting if setting is not None else d))
        with mock.patch.object(pc, "_load", return_value=bundle), mock.patch.object(pc.pagefetch, "fetch", return_value=page), \
             mock.patch.object(pc.page_signals, "extract", return_value={}), mock.patch.dict(sys.modules, {"aidev.core.list_store": fake_ls}), \
             mock.patch.object(core_pkg, "list_store", fake_ls, create=True), mock.patch.object(pc, "enabled", return_value=True):
            pc._cache.clear()
            return pc.predict("https://a.example.com/")

    def test_new_keys_and_old_keys(self):
        r = self._run(self._bundle())
        for k in ("probability", "signals", "final_url", "download", "download_kind", "features", "page_signals", "model_version", "latency_ms"):
            self.assertIn(k, r)
        self.assertIsNotNone(r["probability_calibrated"])
        self.assertEqual(r["threshold"], 0.5)
        self.assertEqual(r["flagged"], r["probability_calibrated"] >= 0.5)

    def test_setting_overrides_stored_threshold(self):
        self.assertEqual(self._run(self._bundle(), setting="0.9")["threshold"], 0.9)

    def test_model_without_calibrator_has_no_threshold(self):
        r = self._run(self._bundle(with_cal=False))
        self.assertIsNone(r["probability_calibrated"])
        self.assertIsNone(r["threshold"])
        self.assertIsNone(r["flagged"])
        self.assertIsNotNone(r["probability"])


if __name__ == "__main__":
    unittest.main()
