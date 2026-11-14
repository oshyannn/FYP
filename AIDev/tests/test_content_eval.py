"""Tests for evaluation/eval_content_own.py and evaluation/campaign_dedup.py.  Run from AIDev/:
    python -m unittest tests.test_content_eval -v
scikit-learn appears ONLY here, as an independent cross-check of the hand-written metrics."""
import unittest

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from aidev.evaluation import campaign_dedup as cd
from aidev.evaluation import eval_content_own as ev


def _synthetic(n=3000, seed=0):
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.3).astype(int)
    p = np.clip(rng.normal(0.25 + 0.5 * y, 0.2), 0, 1)
    return y, p


class MetricTests(unittest.TestCase):
    def test_pr_auc_and_roc_auc_match_sklearn(self):
        y, p = _synthetic()
        self.assertAlmostEqual(ev.pr_auc(y, p), average_precision_score(y, p), places=10)
        self.assertAlmostEqual(ev.roc_auc(y, p), roc_auc_score(y, p), places=10)

    def test_ties_are_one_operating_point(self):
        y = np.array([1, 0, 1, 0, 1, 0])
        p = np.array([0.5] * 6)
        self.assertAlmostEqual(ev.pr_auc(y, p), average_precision_score(y, p), places=10)
        self.assertAlmostEqual(ev.roc_auc(y, p), 0.5)

    def test_recall_at_fpr_respects_budget(self):
        y, p = _synthetic()
        for t in (0.01, 0.005, 0.05):
            r = ev.recall_at_fpr(y, p, t)
            self.assertLessEqual(r["fpr"], t + 1e-12)
            self.assertLessEqual(int(round(r["fpr"] * (y == 0).sum())), r["allowed_fp"])
        self.assertGreater(ev.recall_at_fpr(y, p, 0.05)["recall"], ev.recall_at_fpr(y, p, 0.005)["recall"])

    def test_recall_at_fpr_known_case(self):
        y = np.array([0] * 100 + [1] * 4)
        p = np.concatenate([np.linspace(0, 0.5, 100), [0.9, 0.8, 0.45, 0.3]])
        r = ev.recall_at_fpr(y, p, 0.02)            # 2 benign allowed -> flagged benign must be the top 2 or fewer
        self.assertEqual(r["allowed_fp"], 2)
        self.assertLessEqual(r["fpr"], 0.02)
        # top benign scores are 0.5, 0.495, 0.490; with 2 allowed the threshold must sit above 0.490,
        # so only the phishing pages scoring 0.9 and 0.8 are caught (0.45 and 0.3 are not)
        self.assertEqual(r["recall"], 0.5)
        self.assertGreater(r["threshold"], 0.4898)
        self.assertFalse(r["reliable"])               # fewer than 5 allowed false positives

    def test_calibration_perfect_and_bad(self):
        y = np.array([0, 0, 1, 1])
        self.assertAlmostEqual(ev.brier(y, y.astype(float)), 0.0)
        self.assertAlmostEqual(ev.ece(y, np.array([0.0, 0.0, 1.0, 1.0])), 0.0)
        self.assertGreater(ev.ece(y, np.array([0.9, 0.9, 0.1, 0.1])), 0.5)


class BootstrapTests(unittest.TestCase):
    def test_ci_brackets_point_estimate_and_is_wider_for_clustered_data(self):
        y, p = _synthetic(2000)
        g_unique = np.arange(len(y))
        g_clustered = np.arange(len(y)) // 50          # 40 big groups
        m = {"pr_auc": ev.pr_auc}
        a = ev.cluster_bootstrap(y, p, g_unique, m, n_boot=300)["pr_auc"]
        b = ev.cluster_bootstrap(y, p, g_clustered, m, n_boot=300)["pr_auc"]
        point = ev.pr_auc(y, p)
        self.assertLess(a[0], point)
        self.assertGreater(a[1], point)
        self.assertGreater(b[1] - b[0], a[1] - a[0])    # fewer independent groups -> less certain

    def test_evaluate_report_runs(self):
        y, p = _synthetic(1500)
        src = np.where(y == 1, "phish_feed", np.where(np.arange(len(y)) % 2, "benign_top", "benign_tail"))
        r = ev.evaluate(y, p, np.arange(len(y)) // 3, src, n_boot=50)
        self.assertIn("recall@fpr1%", r["point"])
        self.assertIn("benign_top", r["by_source_at_first_fpr"])
        self.assertIn("recall", r["by_source_at_first_fpr"]["phish_feed"])
        self.assertIn("pr_auc", ev.format_report(r))


KIT = """<html><head><title>Sign in to Maybank2u 123</title>
<script src="https://evil-cdn.example.net/k.js"></script></head>
<body><form action="post.php"><input name=u><input type=password name=p></form></body></html>"""


class FingerprintTests(unittest.TestCase):
    def test_same_kit_on_two_domains_matches(self):
        a = cd.html_fingerprint(KIT, "http://bank-login.example.xyz/a")
        b = cd.html_fingerprint(KIT.replace("123", "987"), "http://other-site.example.top/x/")
        self.assertIsNotNone(a)
        self.assertEqual(a, b)

    def test_different_structure_differs(self):
        a = cd.html_fingerprint(KIT, "http://a.example.xyz/")
        self.assertNotEqual(a, cd.html_fingerprint(KIT.replace("<input name=u>", ""), "http://a.example.xyz/"))      # inputs
        self.assertNotEqual(a, cd.html_fingerprint(KIT.replace("evil-cdn.example.net", "cdn.other.org"), "http://a.example.xyz/"))
        self.assertNotEqual(a, cd.html_fingerprint(KIT.replace('action="post.php"', 'action="https://collect.bad.xyz/g"'), "http://a.example.xyz/"))

    def test_own_domain_assets_are_not_foreign(self):
        h = '<title>x</title><script src="http://a.example.xyz/app.js"></script>'
        self.assertEqual(cd.html_fingerprint(h, "http://a.example.xyz/"), cd.html_fingerprint('<title>x</title>', "http://a.example.xyz/"))

    def test_empty_page_has_no_fingerprint(self):
        self.assertIsNone(cd.html_fingerprint("<html><body>hello</body></html>", "http://a.example.com/"))
        self.assertIsNone(cd.html_fingerprint("", ""))


class ClusterTests(unittest.TestCase):
    def test_shared_fingerprint_merges_domains_including_chains(self):
        domains = ["a.com", "b.com", "c.com", "d.com", "e.com", "f.com"]
        fps = ["k1", "k1", "k2", "k2", None, "k3"]
        # b.com also carries k2 on a second page -> a,b,c,d chain into one cluster
        domains += ["b.com"]
        fps += ["k2"]
        c, rep = cd.campaign_clusters(domains, fps, labels=[1] * 7)
        self.assertEqual(len({c[0], c[1], c[2], c[3], c[6]}), 1)
        self.assertNotEqual(c[4], c[0])
        self.assertNotEqual(c[5], c[0])
        self.assertEqual(rep["n_clusters"], 3)
        self.assertEqual(rep["domains_merged_away"], 3)
        self.assertEqual(rep["pages_without_fingerprint"], 1)

    def test_generic_fingerprint_does_not_merge(self):
        domains = [f"d{i}.com" for i in range(10)]
        c, rep = cd.campaign_clusters(domains, ["g"] * 10, max_domains_per_fp=5)
        self.assertEqual(rep["n_clusters"], 10)
        self.assertEqual(rep["generic_fingerprints_skipped"], 1)

    def test_mixed_label_clusters_are_reported(self):
        c, rep = cd.campaign_clusters(["a.com", "b.com"], ["k", "k"], labels=[0, 1])
        self.assertEqual(rep["mixed_label_clusters"], 1)

    def test_cap_per_cluster(self):
        cluster = np.array([0] * 50 + [1] * 5 + [2] * 30)
        label = np.array([1] * 50 + [1] * 5 + [0] * 30)
        keep, rep = cd.cap_per_cluster(cluster, label, cap=20)
        self.assertEqual(keep[cluster == 0].sum(), 20)
        self.assertEqual(keep[cluster == 1].sum(), 5)
        self.assertEqual(keep[cluster == 2].sum(), 20)
        self.assertEqual(rep["pages_removed"], 30 + 10)
        self.assertEqual(rep["clusters_capped"], 2)
        keep2, _ = cd.cap_per_cluster(cluster, label, cap=20)
        self.assertTrue((keep == keep2).all())          # deterministic


if __name__ == "__main__":
    unittest.main()
