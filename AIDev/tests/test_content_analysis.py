"""Tests for evaluation/feature_coverage.py and evaluation/error_analysis.py.  Run from AIDev/:
    python -m unittest tests.test_content_analysis -v"""
import unittest

import numpy as np
import pandas as pd

from aidev.evaluation import error_analysis as ea
from aidev.evaluation import feature_coverage as fc


class CauseTests(unittest.TestCase):
    def test_fn_rules_in_order(self):
        self.assertIn("shared hosting", ea.cause_fn({"n_words": 500}, True))
        self.assertIn("tiny page", ea.cause_fn({"thin_page": 1}, False))
        self.assertIn("redirector", ea.cause_fn({"n_words": 200, "meta_refresh": 1}, False))
        self.assertIn("no form", ea.cause_fn({"n_words": 200, "n_forms": 0}, False))
        self.assertIn("credential form", ea.cause_fn({"n_words": 200, "n_forms": 1, "has_password_field": 1}, False))
        self.assertIn("nothing sensitive", ea.cause_fn({"n_words": 200, "n_forms": 1}, False))

    def test_fp_rules_in_order(self):
        self.assertIn("login", ea.cause_fp({"has_password_field": 1, "brand_in_meta": 1}))
        self.assertIn("another brand", ea.cause_fp({"brand_in_title_not_domain": 1, "n_words": 500}))
        self.assertIn("tiny", ea.cause_fp({"n_words": 5}))
        self.assertIn("other websites", ea.cause_fp({"n_words": 500, "ext_link_ratio": 0.9}))
        self.assertIn("ordinary", ea.cause_fp({"n_words": 500}))

    def test_defang(self):
        self.assertEqual(ea.defang("http://evil.example.com/a"), "hxxp://evil[.]example[.]com/a")


class AnalyseTests(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(0)
        n = 400
        self.pred = pd.DataFrame({"label": (np.arange(n) % 2), "prob": np.clip(rng.normal(0.3 + 0.4 * (np.arange(n) % 2), 0.25), 0, 1),
                                  "group": np.arange(n) // 3,                      # numeric campaign ids, as train_content2 writes them
                                  "source": np.where(np.arange(n) % 2 == 1, "phish_feed", np.where(np.arange(n) % 4 == 0, "benign_history", "benign_top")),
                                  "url": [f"http://s{i}.example.com/x" for i in range(n)]})
        self.feats = pd.DataFrame({"url": self.pred.url, "group": [f"g{i}.com" if i % 5 else "tinyurl.com" for i in range(n)], "n_words": rng.integers(0, 300, n), "n_forms": rng.integers(0, 3, n),
                                   "has_password_field": rng.integers(0, 2, n), "ext_link_ratio": rng.random(n), "thin_page": 0})

    def test_counts_causes_and_hiding(self):
        r = ea.analyse(self.pred, self.feats, threshold=0.6, n=10, shared={"tinyurl.com"})
        self.assertEqual(sum(r["fn_causes"].values()), r["n_fn"])
        self.assertEqual(sum(r["fp_causes"].values()), r["n_fp"])
        self.assertLessEqual(len(r["fn_sample"]), 10)
        self.assertTrue(all(x["url"].startswith("hxxp") for x in r["fn_sample"]))
        self.assertTrue(all(x["url"] != "" and "history" not in x["url"] or x["source"] == "benign_history" for x in r["fp_sample"]))
        for x in r["fp_sample"]:
            if x["source"] == "benign_history":
                self.assertTrue(x["url"].startswith("(hidden"))
        self.assertIn("shared hosting", " ".join(r["fn_causes"]))
        self.assertIn("# Error analysis", ea.to_markdown(r, "t"))

    def test_default_threshold_is_one_percent_fpr(self):
        r = ea.analyse(self.pred, self.feats, n=5)
        self.assertLessEqual(r["n_fp"] / r["n_benign"], 0.0101)


class CoverageTests(unittest.TestCase):
    def test_share_firing_by_class_and_source(self):
        d = pd.DataFrame({"label": [1, 1, 0, 0], "source": ["p", "p", "b", "b"], "f": [1, 0, 0, 0], "g": [2.0, 1.0, 1.0, 0.0]})
        t = fc.coverage(d, ["f", "g"]).set_index("feature")
        self.assertEqual(t.loc["f", "phishing"], 0.5)
        self.assertEqual(t.loc["f", "benign"], 0.0)
        self.assertEqual(t.loc["g", "benign"], 0.5)
        self.assertEqual(t.loc["g", "p"], 1.0)


if __name__ == "__main__":
    unittest.main()


class SummarizeTests(unittest.TestCase):
    def test_table_and_mean(self):
        import json
        import tempfile
        from pathlib import Path
        from aidev.evaluation import summarize_runs as sr
        with tempfile.TemporaryDirectory() as tmp:
            runs = []
            for i, v in enumerate((0.6, 0.8)):
                p = Path(tmp) / f"r{i}.json"
                p.write_text(json.dumps({"eval_mode": "m", "test_raw": {"point": {"pr_auc": v, "roc_auc": v, "recall@fpr1%": v, "t0.5_accuracy": v, "t0.5_fpr": 0.1}},
                                         "test_calibrated": {"point": {"fixed_recall": v, "fixed_fpr": 0.01}}}))
                runs.append(sr.load_run(p))
            self.assertAlmostEqual(runs[1]["pr_auc"], 0.8)
            self.assertIn("r0", sr.table(runs))
            m = sr.table(runs, mean=True)
            self.assertIn("mean of 2 runs", m)
            self.assertIn("0.700 +- 0.141", m)
