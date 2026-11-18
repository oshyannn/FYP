"""Synthetic-sample tests for the clone diagnostic and same_owner.

These check that the CODE works (skeleton, similarity, same-brand exclusion, same_owner). They do NOT measure
accuracy on real pages. All pages are generated here with a FICTIONAL brand on .test domains (reserved for testing),
so nothing here is a usable copy of a real login page.

Run from AIDev/ with the venv active:
    python -m unittest tests.test_clone_pipeline -v
"""
import unittest

from aidev.evaluation.clone_diagnostic import ReferenceIndex, skeleton
from aidev.evaluation.same_owner import same_owner


def login_page(domain: str, blocks: int = 40, layout: str = "card") -> str:
    """A fictional login page. Same layout + different domain text = a 'clone'. Different layout = unrelated."""
    if layout == "card":
        body = "".join(
            f'<div class="row"><span><a href="https://{domain}/help{i}">help</a></span>'
            f'<p><em>line {i}</em></p></div>' for i in range(blocks))
    else:
        body = "".join(
            f'<table><tr><td><ul><li><b>item {i}</b></li></ul></td></tr></table>' for i in range(blocks))
    return (f'<html><head><title>{domain} sign in</title></head><body>{body}'
            f'<form action="https://{domain}/login"><input type="text"><input type="password"></form>'
            f'</body></html>')


REF_DOMAIN = "examplebank.test"


class ClonePipelineTests(unittest.TestCase):
    def setUp(self):
        ref_html = login_page(REF_DOMAIN, layout="card")
        self.index = ReferenceIndex([(REF_DOMAIN, skeleton(ref_html))])

    def test_clone_scores_high_and_points_to_official(self):
        clone = login_page("examp1ebank.test", layout="card")   # same structure, lookalike domain
        sim, dom = self.index.best(skeleton(clone), "examp1ebank.test")
        self.assertGreaterEqual(sim, 0.9)
        self.assertEqual(dom, REF_DOMAIN)

    def test_unrelated_layout_scores_low(self):
        other = login_page("shop.test", layout="table")
        sim, _ = self.index.best(skeleton(other), "shop.test")
        self.assertLess(sim, 0.3)

    def test_same_domain_is_never_compared(self):
        sim, dom = self.index.best(skeleton(login_page(REF_DOMAIN)), REF_DOMAIN)
        self.assertIsNone(dom)
        self.assertEqual(sim, 0.0)

    def test_same_owner_from_cross_link(self):
        a = '<html><body><a href="https://examplebank.test/">home</a></body></html>'
        b = '<html><body><p>login</p></body></html>'
        res = same_owner("examplebank.test", b, "examplebank-mail.test", a)
        self.assertEqual(res["verdict"], "same")

    def test_unrelated_sites_are_unknown(self):
        a = '<html><body><footer>© 2024 Alpha Foods</footer></body></html>'
        b = '<html><body><footer>© 2024 Beta Travel</footer></body></html>'
        res = same_owner("alpha.test", a, "beta.test", b)
        self.assertEqual(res["verdict"], "unknown")


if __name__ == "__main__":
    unittest.main()
